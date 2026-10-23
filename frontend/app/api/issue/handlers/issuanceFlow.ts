import { NextRequest, NextResponse } from "next/server";
import type { CredentialType } from "@stellarcred/issuer";
import { fetchIssuerPubkey } from "@/lib/issuer-registry";
import { currentDeploymentRef } from "@/lib/deployment";
import { circuitVersionStampFor } from "@/lib/circuit-versions";
import { logger, stripSensitiveFields } from "@/lib/logger";
import { reportError } from "@/lib/error-reporting";
import { env } from "@/lib/env";
import { fetchPlaidBalance } from "@/lib/plaid";
import { personaPendingIdempotencyRecord, type IdempotencyRecord } from "@/lib/idempotency";
import { createPersonaInquiry, resolvePersonaKYC } from "@/lib/persona";
import { registerPendingInquiry } from "@/lib/persona-webhook";
import { issueAndAuditCredentials, localIssuerPubkeyBytes } from "@/lib/issuer-service";
import { checkWalletRateLimit } from "./rateLimit";
import { parseIssueRequestBody, validateIssueRequest } from "./validate";

/**
 * Issuance orchestration for POST /api/issue.
 *
 * Everything from request validation through Persona, Plaid, and credential
 * signing lives here. The route keeps only the transport concerns (request id,
 * idempotency persistence, and the final response headers/log line), so new
 * credential or provider types can be added without growing the dispatcher.
 */

const SIM_ACCOUNT =
  env.NEXT_PUBLIC_ISSUER_ADDRESS ?? "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF";

export interface IssuanceFlowResult {
  /** Response body/status produced by the flow, before transport finalization. */
  response: NextResponse;
  /** Types that were actually requested, used for per-type response logs. */
  credentialTypes: string[];
  issuerId?: string;
  walletAddress?: string;
  outcome: "success" | "failure";
  /**
   * Idempotency record to persist when the flow's outcome is not a completed
   * 200 (currently the Persona redirect marker).
   */
  record?: IdempotencyRecord;
}

/**
 * Runs one issuance request end to end and returns the response plus the
 * metadata the route needs to finalize it. Provider and signing errors are
 * converted into the same responses the route returned before this split.
 */
export async function runIssuanceFlow(
  req: NextRequest,
  requestId: string,
): Promise<IssuanceFlowResult> {
  const parsed = await parseIssueRequestBody(req);
  if (!parsed.ok) {
    return {
      response: parsed.response,
      credentialTypes: [],
      outcome: "failure",
    };
  }

  const walletLimited = checkWalletRateLimit(parsed.body.holder, requestId);
  if (walletLimited) {
    return {
      response: walletLimited,
      credentialTypes: [],
      outcome: "failure",
    };
  }

  const validated = validateIssueRequest(parsed.body, requestId);
  if (!validated.ok) {
    return {
      response: NextResponse.json({ error: validated.error }, { status: validated.status }),
      credentialTypes: validated.credentialTypes,
      issuerId: bodyString(parsed.body.issuerId),
      walletAddress: bodyString(parsed.body.holder),
      outcome: "failure",
    };
  }

/**
 * issuanceFlow.ts — what actually has to happen for a validated issuance
 * request to become signed credentials.
 *
 * The route's only job is to decide *whether* to run this; the sequence —
 * identity (Persona), then balance (Plaid), then signing and stamping — lives
 * here, so a new credential type or provider shows up in one place.
 *
 * The provider stages are deliberately sequential and short-circuiting: a KYC
 * request that has not completed Persona is answered with the redirect, and
 * nothing downstream runs; a failed balance attestation never reaches signing.
 *
 * Two invariants this module is responsible for:
 *
 * 1. **Provider error text never escapes.** `lib/persona.ts` embeds Persona's
 *    response body in the thrown error, and Persona's bodies echo the identity
 *    fields it holds. The catch below therefore drops the message entirely:
 *    not logged, not reported, not returned.
 * 2. **Plaid is the source of truth for `balance`.** A caller-supplied value is
 *    overwritten with the verified aggregate. Only that aggregate is signed;
 *    per-source account detail never leaves this function.
 */

import type { Credential, CredentialType, IssuerClient } from "@stellarcred/issuer";
import { createPersonaInquiry, resolvePersonaKYC } from "@/lib/persona";
import { registerPendingInquiry } from "@/lib/persona-webhook";
import { fetchPlaidBalance } from "@/lib/plaid";
import { issueAndAuditCredentials } from "@/lib/issuer-service";
import { currentDeploymentRef, type DeploymentRef } from "@/lib/deployment";
import { circuitVersionStampFor, type CircuitVersionStamp } from "@/lib/circuit-versions";
import { reportError } from "@/lib/error-reporting";
import { env } from "@/lib/env";
import { logger, stripSensitiveFields } from "@/lib/logger";
import type { IssueRequest } from "./validate";

export interface IssuanceContext {
  requestId: string;
  /** Origin to fall back to for the Persona redirect when BASE_URL is unset. */
  origin: string;
  /** Tenant signing client; omitted for the default single-issuer flow. */
  issuerClient?: IssuerClient;
}

/** A signed credential plus the deployment / circuit it was minted against. */
export type IssuedCredential = Credential & CircuitVersionStamp & { deployment: DeploymentRef };

export type IssuanceOutcome =
  /** The holder must complete (or resume) a Persona inquiry first. */
  | { kind: "persona"; personaUrl: string; inquiryId: string }
  | { kind: "issued"; credentials: IssuedCredential[] }
  /** A provider rejection or signing failure, ready to render as-is. */
  | { kind: "error"; status: number; body: Record<string, unknown> };

/**
 * Run the provider chain and issuance for a validated request.
 *
 * Returns an outcome rather than a `NextResponse` so the route stays the one
 * place that shapes responses, sets `x-request-id`, and writes the idempotency
 * cache — the flow only says what happened.
 */
export async function runIssuanceFlow(
  request: IssueRequest,
  ctx: IssuanceContext,
): Promise<IssuanceOutcome> {
  const { requestId, origin, issuerClient } = ctx;
  const {
    credentialTypes,
    holder,
    issuerId,
    issuerName,
    expiry,
    attributes,
    claimParams,
    personaInquiryId,
    returnUrl,
  } = validated.request;
  const walletAddress = holder;

  const failure = (response: NextResponse): IssuanceFlowResult => ({
    response,
    credentialTypes,
    issuerId,
    walletAddress,
    outcome: "failure",
  });

  if (env.NEXT_PUBLIC_ISSUER_REGISTRY_ID) {
    const registered = await fetchIssuerPubkey(issuerId, SIM_ACCOUNT);
    if (!registered) {
      return failure(jsonError("Selected issuer is not registered on IssuerRegistry.", 400));
    }
    const localKey = localIssuerPubkeyBytes();
    if (!Buffer.from(registered).equals(localKey)) {
      return failure(
        jsonError(
          "ISSUER_PRIVATE_KEY does not match the selected issuer's registered public key on IssuerRegistry. Choose the issuer that matches your server key, or update ISSUER_PRIVATE_KEY.",
          403,
        ),
      );
    }
  }

  // -------------------------------------------------------------------------
  // Identity verification via Persona
  // -------------------------------------------------------------------------
  const needsIdentity = credentialTypes.includes("kyc");
  if (needsIdentity) {
    if (!env.PERSONA_API_KEY) {
      logProviderCall({
        credentialType: "kyc",
        issuerId,
        walletAddress,
        outcome: "demo_mode",
        requestId,
      });
    } else {
      const templateId = env.PERSONA_KYC_TEMPLATE_ID;
      if (!templateId) {
        return failure(
          jsonError("PERSONA_KYC_TEMPLATE_ID is required when PERSONA_API_KEY is set", 500),
        );
      }
      const baseUrl = env.NEXT_PUBLIC_STELLARCRED_BASE_URL ?? req.nextUrl.origin;
      // Every Persona call in this block is wrapped so a provider failure
      // cannot escape the handler. lib/persona.ts embeds Persona's raw error
      // body in the thrown message, and Persona error bodies routinely echo
      // the identity fields Persona holds — an unhandled throw would carry
      // them into the framework's error output. The message is therefore
      // dropped here: not logged, not sent to the error sink, not returned.
      try {
        if (!personaInquiryId) {
          logProviderCall({
            credentialType: "kyc",
            issuerId,
            walletAddress,
            outcome: "inquiry_created",
            requestId,
          });
    claimParams,
    personaInquiryId,
    returnUrl,
  } = request;

  // Copy: the flow owns these from here on (KYC and Plaid both write into it).
  const attributes: Record<string, string> = { ...request.attributes };

  // ---------------------------------------------------------------------------
  // Identity verification via Persona
  // ---------------------------------------------------------------------------
  if (credentialTypes.includes("kyc")) {
    if (!env.PERSONA_API_KEY) {
      logger.info(
        stripSensitiveFields({
          event: "provider_call",
          credentialType: "kyc",
          issuerId,
          walletAddress: holder,
          outcome: "demo_mode",
          requestId,
        }),
      );
    } else {
      const templateId = env.PERSONA_KYC_TEMPLATE_ID;
      if (!templateId) {
        return {
          kind: "error",
          status: 500,
          body: {
            error: "PERSONA_KYC_TEMPLATE_ID is required when PERSONA_API_KEY is set",
          },
        };
      }
      const baseUrl = env.NEXT_PUBLIC_STELLARCRED_BASE_URL ?? origin;

      // Every Persona call in this block is wrapped so a provider failure
      // cannot escape the handler. See invariant (1) in the module header.
      try {
        if (!personaInquiryId) {
          logger.info(
            stripSensitiveFields({
              event: "provider_call",
              credentialType: "kyc",
              issuerId,
              walletAddress: holder,
              outcome: "inquiry_created",
              requestId,
            }),
          );
          const redirectUrl = returnUrl
            ? `${baseUrl}/verify?return_url=${encodeURIComponent(returnUrl)}`
            : `${baseUrl}/verify`;
          const { url, id } = await createPersonaInquiry(templateId, redirectUrl, holder);
          // Keep only the non-PII issuance context server-side so a webhook can
          // complete an approval even when the holder never returns to the tab.
          registerPendingInquiry(id, {
            holder,
            issuerId,
            issuerName,
            expiry,
            credentialTypes: credentialTypes as CredentialType[],
            claimParams,
          });
          return {
            response: NextResponse.json(
              { needsPersona: true, personaUrl: url, inquiryId: id },
              { status: 202 },
            ),
            credentialTypes,
            issuerId,
            walletAddress,
            outcome: "failure",
            record: personaPendingIdempotencyRecord(id, url),
          };
          return { kind: "persona", personaUrl: url, inquiryId: id };
        }

        const kyc = await resolvePersonaKYC(personaInquiryId);
        if (!kyc.ok) {
          logProviderCall({
            credentialType: "kyc",
            issuerId,
            walletAddress,
            outcome: "verification_failed",
            requestId,
          });
          return failure(jsonError(kyc.error ?? "Identity verification failed", 403));
        }
        logProviderCall({
          credentialType: "kyc",
          issuerId,
          walletAddress,
          outcome: "verified",
          requestId,
        });
          logger.info(
            stripSensitiveFields({
              event: "provider_call",
              credentialType: "kyc",
              issuerId,
              walletAddress: holder,
              outcome: "verification_failed",
              requestId,
            }),
          );
          return {
            kind: "error",
            status: 403,
            body: { error: kyc.error ?? "Identity verification failed" },
          };
        }

        logger.info(
          stripSensitiveFields({
            event: "provider_call",
            credentialType: "kyc",
            issuerId,
            walletAddress: holder,
            outcome: "verified",
            requestId,
          }),
        );
        if (kyc.dob) attributes.date_of_birth = kyc.dob;
        if (kyc.countryNumeric) attributes.country_code = kyc.countryNumeric;
      } catch {
        logger.error(
          stripSensitiveFields({
            event: "provider_call",
            credentialType: "kyc",
            issuerId,
            walletAddress,
            walletAddress: holder,
            outcome: "provider_unavailable",
            requestId,
          }),
        );
        return failure(
          jsonError("Identity verification service is unavailable. Please try again.", 502),
        );
      }
    }
  }

  // Gate funds issuance on the Plaid balance attestation. Plaid is the source
  // of truth — we overwrite any user-supplied balance with the verified
  // aggregate (summed across every linked Plaid item). Only the aggregate is
  // committed and signed; per-source account data never leaves this server.
  const needsFunds = credentialTypes.includes("funds");
  if (needsFunds) {
    const plaid = await fetchPlaidBalance(requestId);
    if (!plaid.ok) {
      logProviderCall({
        credentialType: "funds",
        issuerId,
        walletAddress,
        outcome: "verification_failed",
        requestId,
      });
      return failure(
        NextResponse.json({ error: plaid.error, code: plaid.code }, { status: plaid.status }),
      );
    }
    logProviderCall({
      credentialType: "funds",
      issuerId,
      walletAddress,
      outcome: "verified",
      requestId,
    });
    attributes.balance = String(plaid.balance ?? 0);
  }

        return {
          kind: "error",
          status: 502,
          body: {
            error: "Identity verification service is unavailable. Please try again.",
          },
        };
      }
    }
  }

  // ---------------------------------------------------------------------------
  // Balance attestation via Plaid
  // ---------------------------------------------------------------------------
  if (credentialTypes.includes("funds")) {
    const plaid = await fetchPlaidBalance(requestId);
    if (!plaid.ok) {
      logger.info(
        stripSensitiveFields({
          event: "provider_call",
          credentialType: "funds",
          issuerId,
          walletAddress: holder,
          outcome: "verification_failed",
          requestId,
        }),
      );
      return {
        kind: "error",
        status: plaid.status,
        body: { error: plaid.error, code: plaid.code },
      };
    }

    logger.info(
      stripSensitiveFields({
        event: "provider_call",
        credentialType: "funds",
        issuerId,
        walletAddress: holder,
        outcome: "verified",
        requestId,
      }),
    );
    attributes.balance = String(plaid.balance ?? 0);
  }

  // ---------------------------------------------------------------------------
  // Signing
  // ---------------------------------------------------------------------------
  try {
    const issuedCredentials = await issueAndAuditCredentials({
      credentialTypes,
      holder,
      issuerId,
      issuerName,
      expiry,
      attributes,
      claimParams,
      requestId,
    });
      issuerClient,
    });

    // Stamp the deployment and the circuit version on every credential at mint
    // time (#545, #633). The circuit version is what lets the holder's device
    // detect — before proving, with a message naming both versions — that the
    // circuit this credential was issued against is no longer the one this app
    // serves, instead of surfacing it later as an invalid witness.
    const credentials = issuedCredentials.map((credential) => ({
    const credentials: IssuedCredential[] = issuedCredentials.map((credential) => ({
      ...credential,
      deployment: currentDeploymentRef(),
      ...circuitVersionStampFor(credential.type),
    }));

    return {
      response: NextResponse.json({ credentials }),
      credentialTypes,
      issuerId,
      walletAddress,
      outcome: "success",
    };
    return { kind: "issued", credentials };
  } catch (e) {
    for (const type of credentialTypes) {
      logger.error(
        stripSensitiveFields({
          event: "signing_failed",
          credentialType: type,
          issuerId,
          walletAddress,
          walletAddress: holder,
          error: (e as Error).message,
          requestId,
        }),
      );
    }
    // Report the error to the webhook with the exception forwarded so that
    // safeErrorMessage can strip stack frames and PII patterns before any
    // data leaves the process (issue #553).
    void reportError({
      method: "POST",
      path: "/api/issue",
      requestId,
      status: 500,
      exception: e,
    });
    return failure(jsonError((e as Error).message, 500));
  }
}

function jsonError(error: string, status: number): NextResponse {
  return NextResponse.json({ error }, { status });
}

function bodyString(value: unknown): string | undefined {
  return typeof value === "string" && value.length > 0 ? value : undefined;
}

function logProviderCall({
  credentialType,
  issuerId,
  walletAddress,
  outcome,
  requestId,
}: {
  credentialType: "kyc" | "funds";
  issuerId: string;
  walletAddress: string;
  outcome: string;
  requestId: string;
}): void {
  logger.info(
    stripSensitiveFields({
      event: "provider_call",
      credentialType,
      issuerId,
      walletAddress,
      outcome,
      requestId,
    }),
  );
}
    return {
      kind: "error",
      status: 500,
      body: { error: (e as Error).message },
    };
  }
}
