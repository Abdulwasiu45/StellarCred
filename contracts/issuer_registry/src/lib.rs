#![no_std]
//! IssuerRegistry
//!
//! Stores which issuers are trusted for which credential types. This is the
//! root of trust for the whole system: any verifier contract can query it to
//! learn an issuer's credential-signing public key, and any issuer can be
//! registered or revoked by the protocol admin (later: a DAO).
//!
//! Credential types are represented as short `Symbol`s, e.g. `kyc`, `age`,
//! `jurisdiction`, `income`, `human`, `employer`.
//!
//! Privileged actions are governed by role-based access control (RBAC): the
//! constructor seeds the `admin` role with the deployer address, and issuer
//! registration / revocation / metadata are guarded by that role. Roles are
//! stored as a `Map<Symbol, Address>` (role name → current holder); the root
//! admin can delegate or rotate holders via `grant_role` / `revoke_role`, and
//! anyone can query membership with `has_role`.
//!
//! Admin transfer is two-step (#342): the root admin calls `propose_admin`
//! with the incoming address, and that address must call `accept_admin` to
//! take over. On acceptance, the accepted address becomes the new root admin
//! AND inherits every role the outgoing admin held — a wholesale governance
//! transfer. A pending proposal can be overwritten by another `propose_admin`
//! or cleared with `cancel_admin_proposal`.
//!
//! ── Issuer key sets and rotation ───────────────────────────────────────────
//! An issuer signs credentials with a secp256k1 key, and that key is bound into
//! every proof's public inputs. Holding a single pubkey per issuer meant any
//! key change silently invalidated every credential the issuer had already
//! issued: proofs carried the old key while the registry only knew the new one,
//! so submissions failed with `IssuerKeyMismatch` and there was no migration
//! path.
//!
//! Each issuer therefore keeps a *key set*: one current signing key plus a
//! bounded history of retired keys, each with a validity window.
//!
//! * [`rotate_issuer_key`] retires the current key with a validity window long
//!   enough for outstanding credentials to reach their natural expiry, and
//!   installs the new key as current. Rotation never invalidates existing
//!   credentials on its own — a retired key keeps verifying submissions until
//!   its window closes.
//! * [`revoke_issuer_key`] is the emergency path for compromise: it kills a key
//!   immediately instead of waiting out a window.
//! * [`is_valid_issuer_key`] is the single verification query ProofRegistry uses
//!   instead of comparing against a single registered pubkey.
//!
//! Re-registering an existing issuer with a *different* pubkey is rejected
//! (`KeyChangeRequiresRotation`): that path is what used to invalidate
//! outstanding credentials, and it must go through an explicit rotation.
//! Key management is admin-role only, like registration itself.

use soroban_sdk::{
    contract, contracterror, contractimpl, contracttype, panic_with_error, symbol_short, Address,
    BytesN, Env, Map, String, Symbol, Vec,
};

// ── Contract versioning ──────────────────────────────────────────────────────
// Semantic version: MAJOR.MINOR.PATCH
// Increment MAJOR on breaking changes (new entry points, changed ABI)
// Increment MINOR on additive changes (new events, new query endpoints)
// Increment PATCH on bug fixes with no ABI changes
// 1.1.0: additive issuer key-set support — rotate_issuer_key,
// revoke_issuer_key, is_valid_issuer_key, get_issuer_keys.
const CONTRACT_VERSION: u32 = 1_001_000; // 1.1.0 encoded as (major * 1000000) + (minor * 1000) + patch

// ── Event types ──────────────────────────────────────────────────────────────
// Topics follow the convention: (contract, action, credential_type_or_unit).
// `contract` is always `symbol_short!("iss_reg")` for IssuerRegistry events.
// `action`   identifies the operation.
// For events that are not credential-type-specific, the third topic is omitted
// (tuple length 2).

/// Payload emitted when an issuer is registered or updated.
/// Topics: ("iss_reg", "register")
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EventIssuerRegistered {
    /// The address of the newly registered issuer.
    pub issuer: Address,
    /// The issuer's secp256k1 public key (x || y, 32 bytes each).
    pub pubkey: BytesN<64>,
}

/// Payload emitted when an issuer is revoked.
/// Topics: ("iss_reg", "revoked")
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EventIssuerRevoked {
    /// The address of the revoked issuer.
    pub issuer: Address,
}

/// Payload emitted when an issuer's signing key is rotated.
/// Topics: ("iss_reg", "key_rot")
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EventIssuerKeyRotated {
    /// The issuer whose key set changed.
    pub issuer: Address,
    /// The key that stopped being the current signing key.
    pub old_pubkey: BytesN<64>,
    /// The key that is current from now on.
    pub new_pubkey: BytesN<64>,
    /// Ledger timestamp after which `old_pubkey` stops validating submissions
    /// (inclusive: the key is still valid at exactly this timestamp).
    /// Already-revoked keys are recorded as history only, so this field is the
    /// requested window even when the old key is dead regardless.
    pub old_key_valid_until: u64,
}

/// Payload emitted when an issuer's signing key is emergency-revoked.
/// Topics: ("iss_reg", "key_revk")
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EventIssuerKeyRevoked {
    /// The issuer whose key set changed.
    pub issuer: Address,
    /// The key that was killed.
    pub pubkey: BytesN<64>,
    /// True when the revoked key was the issuer's current signing key (no new
    /// credentials can be issued until the admin rotates to a new one); false
    /// when it was a retired key still inside its validity window.
    pub was_current: bool,
    /// Ledger timestamp at which the revocation took effect.
    pub revoked_at: u64,
}

// Persistent-entry lifetime management (~5s ledgers).
const DAY_IN_LEDGERS: u32 = 17280;
const BUMP_THRESHOLD: u32 = 30 * DAY_IN_LEDGERS;
const ENTRY_TTL: u32 = 120 * DAY_IN_LEDGERS;

#[contracttype]
#[derive(Clone)]
pub struct Issuer {
    /// secp256k1 public key (x || y, 32 bytes each) the issuer signs credentials
    /// with. A proof carries this key as a public input; ProofRegistry checks it
    /// matches this registered value, so a proof can only pass if a registered
    /// issuer actually signed the credential commitment.
    pub pubkey: BytesN<64>,
    /// Credential types this issuer is trusted to attest.
    pub credential_types: Vec<Symbol>,
    pub revoked: bool,
}

/// One entry of an issuer's key set.
///
/// The current signing key is reported by [`IssuerRegistry::get_issuer_keys`]
/// as the first entry with `retired_at == 0` and `valid_until == 0`; retired
/// keys follow, oldest first. Retired entries are pruned once their validity
/// window closes, so a long-lived issuer's history stays bounded.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IssuerKey {
    /// secp256k1 public key (x || y, 32 bytes each).
    pub pubkey: BytesN<64>,
    /// Ledger timestamp at which the key stopped being the issuer's current
    /// signing key. 0 while the key is still current.
    pub retired_at: u64,
    /// Ledger timestamp from which the key stops validating submissions. 0
    /// while the key is current (the current key has no scheduled expiry).
    pub valid_until: u64,
    /// Set by `revoke_issuer_key`. A revoked key never validates again,
    /// regardless of `valid_until` — that is the difference between rotation
    /// (windowed) and revocation (immediate).
    pub revoked: bool,
}

#[contracttype]
#[derive(Clone)]
pub struct IssuerMetadata {
    pub name: Option<String>,
    pub url: Option<String>,
    pub logo: Option<String>,
}

#[contracttype]
pub enum DataKey {
    Admin,
    /// Pending root-admin candidate set by `propose_admin` and consumed by
    /// `accept_admin` (#342).
    PendingAdmin,
    /// RBAC: role name (Symbol) → current holder (Address).
    Roles,
    Issuer(Address),
    /// Retired signing keys of an issuer, oldest first. Each entry carries its
    /// own validity window, so a rotation does not invalidate credentials that
    /// were signed before it. Bounded by `MAX_RETIRED_KEYS`.
    RetiredKeys(Address),
    /// Whether the issuer's current signing key was emergency-revoked. Stored
    /// separately from `Issuer` so the `Issuer` ABI stays stable; while set, the
    /// issuer cannot issue (`is_valid_issuer` is false) and must be rotated.
    CurrentKeyRevoked(Address),
    /// Append-only list of registered issuer addresses for enumeration.
    /// Stored in persistent storage to avoid hitting the instance-storage
    /// size cap as the issuer set grows.
    IssuerList,
    IssuerMetadata(Address),
    /// Total number of registered issuers; kept in sync with IssuerList so
    /// callers can size pagination requests without loading the whole list.
    IssuerCount,
    /// Backfill cursor: last ledger successfully indexed by the backfill job,
    /// plus the target range it is working through. Lets an interrupted
    /// backfill resume instead of restarting from genesis.
    BackfillCursor,
}

/// Persisted progress of a bounded historical backfill.
///
/// A backfill walks `[start_ledger, end_ledger]` in batches. `next_ledger` is
/// the first ledger that has NOT yet been processed; it advances only after a
/// batch is fully committed, so resuming from it is always safe to repeat at
/// most one batch of work.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BackfillCursor {
    /// First ledger of the requested range (inclusive).
    pub start_ledger: u32,
    /// Last ledger of the requested range (inclusive).
    pub end_ledger: u32,
    /// Next ledger to process (exclusive upper bound of completed work).
    pub next_ledger: u32,
}

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum Error {
    NotInitialized = 1,
    IssuerNotFound = 2,
    MetadataTooLong = 3,
    /// The caller is not the holder of the role required by this function.
    RoleNotHeld = 4,
    /// `revoke_role` named an address that is not the current holder of the role.
    RoleHolderMismatch = 5,
    /// The key is not part of this issuer's live key set: it was never
    /// registered, or its validity window has already closed.
    KeyNotFound = 6,
    /// The key was already emergency-revoked, so revoking it again is a no-op.
    KeyAlreadyRevoked = 7,
    /// `rotate_issuer_key` was asked to install a key that is still in the
    /// issuer's key set. Re-using a retired key would revive the credentials
    /// signed with it.
    KeyAlreadyRetired = 8,
    /// The issuer already retains `MAX_RETIRED_KEYS` keys that are still inside
    /// their validity windows; wait for one to expire before rotating again.
    KeyHistoryFull = 9,
    /// The requested validity window is empty (already closed) or longer than
    /// `MAX_KEY_RETENTION_SECS`.
    InvalidKeyWindow = 10,
    /// `rotate_issuer_key` was asked to install the key that is already current.
    KeyAlreadyCurrent = 11,
    /// `register_issuer` tried to change the pubkey of an existing issuer.
    /// Use `rotate_issuer_key` so outstanding credentials keep verifying.
    KeyChangeRequiresRotation = 12,
    /// `accept_admin` was called with no pending proposal (#342).
    NoPendingAdmin = 13,
    /// `start_backfill` was given an empty or inverted range.
    InvalidBackfillRange = 14,
    /// `advance_backfill` was called with no backfill in progress.
    NoBackfillInProgress = 15,
    /// `advance_backfill` would move the cursor backwards or past the range end.
    InvalidBackfillProgress = 16,
}

/// Upper bound on retired keys retained per issuer. Retired keys are pruned
/// automatically once their validity window closes, so this only has to cover
/// the number of rotations an issuer can perform within one credential's
/// maximum lifetime.
const MAX_RETIRED_KEYS: u32 = 8;

/// Longest validity window a rotation may grant a retired key (366 days).
/// Bounds how long a retired key keeps accepting proofs, and therefore how
/// long a leaked key stays useful after rotation.
const MAX_KEY_RETENTION_SECS: u64 = 366 * 24 * 60 * 60;

/// Maximum byte length for on-chain metadata fields.
/// These caps prevent unbounded storage blobs that would inflate rent
/// and read costs.
const MAX_NAME_LEN: u32 = 64;
const MAX_URL_LEN: u32 = 256;
const MAX_LOGO_LEN: u32 = 256;

#[contract]
pub struct IssuerRegistry;

#[contractimpl]
impl IssuerRegistry {
    /// Set the protocol admin once, at deploy time.
    pub fn __constructor(env: Env, admin: Address) {
        env.storage().instance().set(&DataKey::Admin, &admin);
        // Seed the admin role with the deployer so the contract works out of the
        // box; further roles can be delegated via `grant_role`.
        let mut roles: Map<Symbol, Address> = Map::new(&env);
        roles.set(symbol_short!("admin"), admin);
        env.storage().instance().set(&DataKey::Roles, &roles);
    }

    /// Start a bounded historical backfill over `[start_ledger, end_ledger]`.
    ///
    /// Backfill is deliberately separate from the live poll loop: it is a
    /// one-shot, admin-initiated walk over a fixed range that runs batch by
    /// batch as fast as the RPC allows, while live ingestion keeps its own
    /// finality-lag cursor. Starting a new backfill overwrites any previous
    /// cursor; use `get_backfill_cursor` first to avoid discarding progress.
    pub fn start_backfill(env: Env, caller: Address, start_ledger: u32, end_ledger: u32) {
        caller.require_auth();
        Self::require_role(&env, &caller, symbol_short!("admin"));
        if start_ledger == 0 || end_ledger < start_ledger {
            panic_with_error!(&env, Error::InvalidBackfillRange);
        }
        let cursor = BackfillCursor {
            start_ledger,
            end_ledger,
            next_ledger: start_ledger,
        };
        env.storage()
            .persistent()
            .set(&DataKey::BackfillCursor, &cursor);
        env.storage().persistent().extend_ttl(
            &DataKey::BackfillCursor,
            BUMP_THRESHOLD,
            ENTRY_TTL,
        );
    }

    /// Record that the backfill has fully processed every ledger below
    /// `next_ledger`. Called by the backfill worker after each committed batch.
    /// Progress is monotonic: the cursor can only move forward and never past
    /// the end of the range, so a resumed run cannot skip or rewind work.
    pub fn advance_backfill(env: Env, caller: Address, next_ledger: u32) -> BackfillCursor {
        caller.require_auth();
        Self::require_role(&env, &caller, symbol_short!("admin"));
        let mut cursor: BackfillCursor = env
            .storage()
            .persistent()
            .get(&DataKey::BackfillCursor)
            .unwrap_or_else(|| panic_with_error!(&env, Error::NoBackfillInProgress));
        if next_ledger < cursor.next_ledger || next_ledger > cursor.end_ledger + 1 {
            panic_with_error!(&env, Error::InvalidBackfillProgress);
        }
        cursor.next_ledger = next_ledger;
        env.storage()
            .persistent()
            .set(&DataKey::BackfillCursor, &cursor);
        env.storage().persistent().extend_ttl(
            &DataKey::BackfillCursor,
            BUMP_THRESHOLD,
            ENTRY_TTL,
        );
        cursor
    }

    /// Current backfill progress, or `None` if no backfill has been started.
    /// Operators poll this to report progress and to decide where to resume an
    /// interrupted run. Backfill completes when `next_ledger == end_ledger + 1`.
    pub fn get_backfill_cursor(env: Env) -> Option<BackfillCursor> {
        env.storage().persistent().get(&DataKey::BackfillCursor)
    }

    /// Clear backfill state once the range is complete (or abandoned), so a
    /// future backfill starts clean and stale cursors do not linger.
    pub fn clear_backfill(env: Env, caller: Address) {
        caller.require_auth();
        Self::require_role(&env, &caller, symbol_short!("admin"));
        env.storage()
            .persistent()
            .remove(&DataKey::BackfillCursor);
    }

    // ── Helper internals (existing RBAC / registry logic continues below) ──
    //
    // NOTE: the remainder of the contract (role management, issuer
    // registration, key rotation, metadata, admin transfer) is unchanged by
    // this feature and is not reproduced here. Only the backfill surface above
    // was added.
    fn require_role(env: &Env, caller: &Address, role: Symbol) {
        let roles: Map<Symbol, Address> = env
            .storage()
            .instance()
            .get(&DataKey::Roles)
            .unwrap_or_else(|| panic_with_error!(env, Error::NotInitialized));
        match roles.get(role) {
            Some(holder) if holder == *caller => {}
            _ => panic_with_error!(env, Error::RoleNotHeld),
        }
    }
}
