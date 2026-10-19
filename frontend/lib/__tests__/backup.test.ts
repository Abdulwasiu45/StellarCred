import { beforeEach, describe, expect, it, vi } from "vitest";
import type { DeploymentRef } from "../deployment";

const TESTNET_PASSPHRASE = "Test SDF Network ; September 2015";
const MAINNET_PASSPHRASE = "Public Global Stellar Network ; September 2015";

const CURRENT_CONTRACTS = {
  issuerRegistry: "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAMOCKR",
  credentialVerifier: "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAMOCKV",
  proofRegistry: "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAMOCKP",
  gatedPool: "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAMOCKG",
};

vi.mock("../stellar", () => ({
  NETWORK: "testnet",
  NETWORK_PASSPHRASE: TESTNET_PASSPHRASE,
  CONTRACTS: { ...CURRENT_CONTRACTS },
  CREDENTIAL_TYPES: [
    "kyc",
    "age",
    "jurisdiction",
    "income",
    "funds",
    "accreditation",
    "employment",
  ],
}));

const { createEncryptedBackup, decryptBackup, mergeCredentials } = await import("../backup");
const { CREDENTIALS_STORAGE_KEY } = await import("../credential");

const PASSPHRASE = "correct horse battery staple";

function deploymentRef(networkPassphrase: string): DeploymentRef {
  return {
    network: networkPassphrase === TESTNET_PASSPHRASE ? "testnet" : "mainnet",
    networkPassphrase,
    contracts: { ...CURRENT_CONTRACTS },
  };
}

function storedCredential(deployment?: unknown) {
  return {
    type: "kyc",
    title: "KYC Complete",
    claim: "identity verified",
    issuer: "Test Issuer",
    issuerId: "GABCDEFGHIJKLMNOPQRSTUVWXYZ234567ABCDEFGHIJKLMNOPQRSTUVWXY234",
    holder: "GTESTHOLDER",
    value: "0x1234",
    salt: "0xabcd",
    commitment: "0xdeadbeef",
    sig: Array(64).fill(7),
    issuerPubX: Array(32).fill(1),
    issuerPubY: Array(32).fill(2),
    issuedAt: 1700000000,
    expiry: "30 days",
    ...(deployment ? { deployment } : {}),
  };
}

beforeEach(() => {
  localStorage.clear();
});

describe("createEncryptedBackup", () => {
  it("records the current deployment in the (plaintext) envelope", async () => {
    localStorage.setItem(CREDENTIALS_STORAGE_KEY, JSON.stringify([storedCredential()]));
    const backup = await createEncryptedBackup(PASSPHRASE);
    expect(backup.version).toBe(2);
    expect(backup.deployment).toEqual(deploymentRef(TESTNET_PASSPHRASE));
  });
});

describe("decryptBackup cross-deployment guard (#545)", () => {
  it("rejects a backup whose envelope deployment is on another network", async () => {
    localStorage.setItem(CREDENTIALS_STORAGE_KEY, JSON.stringify([storedCredential()]));
    const backup = await createEncryptedBackup(PASSPHRASE);
    backup.deployment = deploymentRef(MAINNET_PASSPHRASE);

    await expect(decryptBackup(backup, PASSPHRASE)).rejects.toThrow(
      /belongs to another deployment/,
    );
  });

  it("rejects a backup whose credentials carry a foreign deployment even without the envelope field", async () => {
    localStorage.setItem(
      CREDENTIALS_STORAGE_KEY,
      JSON.stringify([storedCredential(deploymentRef(MAINNET_PASSPHRASE))]),
    );
    const backup = await createEncryptedBackup(PASSPHRASE);
    // Simulate an envelope written by an older exporter that predates the
    // plaintext deployment field — the per-credential check must still fire.
    delete (backup as { deployment?: unknown }).deployment;

    await expect(decryptBackup(backup, PASSPHRASE)).rejects.toThrow(
      /belongs to another deployment/,
    );
  });

  it("round-trips a backup from this deployment", async () => {
    const cred = storedCredential(deploymentRef(TESTNET_PASSPHRASE));
    localStorage.setItem(CREDENTIALS_STORAGE_KEY, JSON.stringify([cred]));
    const backup = await createEncryptedBackup(PASSPHRASE);

    const restored = await decryptBackup(backup, PASSPHRASE);
    expect(restored).toHaveLength(1);
    expect(restored[0].commitment).toBe(cred.commitment);
  });
});

describe("mergeCredentials cross-deployment guard (#545)", () => {
  it("refuses to merge a foreign-deployment credential", async () => {
    localStorage.setItem(CREDENTIALS_STORAGE_KEY, JSON.stringify([]));
    await expect(
      mergeCredentials([storedCredential(deploymentRef(MAINNET_PASSPHRASE)) as never]),
    ).rejects.toThrow(/belongs to another deployment/);
  });
});
