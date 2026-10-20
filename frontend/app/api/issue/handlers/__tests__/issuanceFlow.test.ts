// @vitest-environment node
//
// Orchestration unit tests for ./handlers/issuanceFlow.ts. Providers, the
// issuer service, and the audit/error sinks are mocked so each branch can be
// exercised without signing real commitments.

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { NextRequest } from "next/server";

// Env is read once at module load (lib/env.ts), so provide the Persona values
// this suite needs before any import is evaluated.
vi.hoisted(() => {
  process.env.PERSONA_API_KEY ??= "test-persona-key";
  process.env.PERSONA_KYC_TEMPLATE_ID ??= "itmpl_test";
});

const mocks = vi.hoisted(() => ({
  fetchIssuerPubkey: vi.fn(),
  localIssuerPubkeyBytes: vi.fn(),
  issueAndAuditCredentials: vi.fn(),
  createPersonaInquiry: vi.fn(),
  resolvePersonaKYC: vi.fn(),
  registerPendingInquiry: vi.fn(),
  fetchPlaidBalance: vi.fn(),
  reportError: vi.fn(),
}));

vi.mock("@/lib/issuer-registry", () => ({
  fetchIssuerPubkey: mocks.fetchIssuerPubkey,
}));

vi.mock("@/lib/issuer-service", () => ({
  issueAndAuditCredentials: mocks.issueAndAuditCredentials,
  localIssuerPubkeyBytes: mocks.localIssuerPubkeyBytes,
}));

vi.mock("@/lib/persona", () => ({
  createPersonaInquiry: mocks.createPersonaInquiry,
  resolvePersonaKYC: mocks.resolvePersonaKYC,
}));

vi.mock("@/lib/persona-webhook", () => ({
  registerPendingInquiry: mocks.registerPendingInquiry,
}));

vi.mock("@/lib/plaid", () => ({
  fetchPlaidBalance: mocks.fetchPlaidBalance,
}));

vi.mock("@/lib/error-reporting", () => ({
  reportError: mocks.reportError,
}));

vi.mock("@/lib/deployment", () => ({
  currentDeploymentRef: () => ({
    network: "testnet",
    proofRegistryId: "C_PROOF_REGISTRY",
    issuerRegistryId: "C_ISSUER_REGISTRY",
  }),
}));

vi.mock("@/lib/circuit-versions", () => ({
  circuitVersionStampFor: (type: string) => ({
    circuitVersion: `v1-${type}`,
    circuitVkVersion: 1,
  }),
}));

import { runIssuanceFlow } from "../issuanceFlow";
import { rateLimitClear } from "@/lib/rate-limit";

const HOLDER = "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF";
const ISSUER_ID = "GBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBHF2";

const savedWalletLimit = process.env.RATE_LIMIT_ISSUE_WALLET;

beforeEach(() => {
  vi.clearAllMocks();
  rateLimitClear();
  delete process.env.RATE_LIMIT_ISSUE_WALLET;
  mocks.issueAndAuditCredentials.mockResolvedValue([credential()]);
});

afterEach(() => {
  if (savedWalletLimit === undefined) delete process.env.RATE_LIMIT_ISSUE_WALLET;
  else process.env.RATE_LIMIT_ISSUE_WALLET = savedWalletLimit;
  rateLimitClear();
});

function credential(type = "age") {
  return {
    type,
    title: "Age Verified",
    claim: "age ≥ 18",
    issuer: "StellarCred Authority",
    issuerId: ISSUER_ID,
    holder: HOLDER,
    value: "9300",
    salt: "0xabc123",
    commitment: "0xdeadbeef",
    sig: Array.from({ length: 64 }, () => 1),
    issuerPubX: Array.from({ length: 32 }, () => 2),
    issuerPubY: Array.from({ length: 32 }, () => 3),
    issuedAt: 1_700_000_000,
    expiry: "90 days",
  };
}

function postRequest(payload: unknown): NextRequest {
  return new NextRequest("http://localhost/api/issue", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
}

const ageBody = {
  credential_types: ["age"],
  holder: HOLDER,
  issuerId: ISSUER_ID,
  attributes: { date_of_birth: "1995-06-15" },
};

describe("runIssuanceFlow — issuance", () => {
  it("signs the requested credentials and stamps deployment + circuit version", async () => {
    const result = await runIssuanceFlow(postRequest(ageBody), "req-1");

    expect(result.response.status).toBe(200);
    expect(result.outcome).toBe("success");
    expect(result.credentialTypes).toEqual(["age"]);
    expect(result.issuerId).toBe(ISSUER_ID);
    expect(result.walletAddress).toBe(HOLDER);

    const body = await result.response.json();
    expect(body.credentials).toHaveLength(1);
    expect(body.credentials[0]).toMatchObject({
      type: "age",
      deployment: {
        network: "testnet",
        proofRegistryId: "C_PROOF_REGISTRY",
        issuerRegistryId: "C_ISSUER_REGISTRY",
      },
      circuitVersion: "v1-age",
      circuitVkVersion: 1,
    });

    expect(mocks.issueAndAuditCredentials).toHaveBeenCalledWith({
      credentialTypes: ["age"],
      holder: HOLDER,
      issuerId: ISSUER_ID,
      issuerName: "StellarCred Authority",
      expiry: "90 days",
      attributes: { date_of_birth: "1995-06-15" },
      claimParams: undefined,
      requestId: "req-1",
    });
  });

  it("turns a signing failure into a 500 and reports it", async () => {
    mocks.issueAndAuditCredentials.mockRejectedValue(new Error("signing exploded"));

    const result = await runIssuanceFlow(postRequest(ageBody), "req-2");

    expect(result.response.status).toBe(500);
    expect(result.outcome).toBe("failure");
    await expect(result.response.json()).resolves.toEqual({
      error: "signing exploded",
    });
    expect(mocks.reportError).toHaveBeenCalledWith(
      expect.objectContaining({
        path: "/api/issue",
        requestId: "req-2",
        status: 500,
      }),
    );
  });
});

describe("runIssuanceFlow — validation and rate limiting", () => {
  it("returns 400 for an invalid credential type without signing", async () => {
    const result = await runIssuanceFlow(
      postRequest({
        credential_types: ["not-a-real-type"],
        holder: HOLDER,
        issuerId: ISSUER_ID,
      }),
      "req-3",
    );

    expect(result.response.status).toBe(400);
    expect(result.outcome).toBe("failure");
    expect(result.credentialTypes).toEqual(["not-a-real-type"]);
    await expect(result.response.json()).resolves.toEqual({
      error: "Invalid credential type: not-a-real-type",
    });
    expect(mocks.issueAndAuditCredentials).not.toHaveBeenCalled();
  });

  it("returns 400 for malformed JSON without signing", async () => {
    const result = await runIssuanceFlow(
      new NextRequest("http://localhost/api/issue", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: "{not-json",
      }),
      "req-4",
    );

    expect(result.response.status).toBe(400);
    expect(result.outcome).toBe("failure");
    await expect(result.response.json()).resolves.toMatchObject({
      code: "invalid_json",
    });
    expect(mocks.issueAndAuditCredentials).not.toHaveBeenCalled();
  });

  it("returns 429 when the holder exceeds the wallet limit", async () => {
    process.env.RATE_LIMIT_ISSUE_WALLET = "1";

    const first = await runIssuanceFlow(postRequest(ageBody), "req-5");
    const second = await runIssuanceFlow(postRequest(ageBody), "req-6");

    expect(first.response.status).toBe(200);
    expect(second.response.status).toBe(429);
    await expect(second.response.json()).resolves.toMatchObject({
      code: "rate_limited",
    });
    expect(mocks.issueAndAuditCredentials).toHaveBeenCalledTimes(1);
  });
});

describe("runIssuanceFlow — Persona", () => {
  const kycBody = {
    credential_types: ["kyc"],
    holder: HOLDER,
    issuerId: ISSUER_ID,
  };

  it("creates an inquiry, registers pending context, and returns a redirect marker", async () => {
    mocks.createPersonaInquiry.mockResolvedValue({
      url: "https://withpersona.com/verify?inquiry=inq_1",
      id: "inq_1",
    });

    const result = await runIssuanceFlow(postRequest(kycBody), "req-7");

    expect(result.response.status).toBe(202);
    expect(result.record).toMatchObject({
      kind: "persona_pending",
      inquiryId: "inq_1",
      personaUrl: "https://withpersona.com/verify?inquiry=inq_1",
    });
    await expect(result.response.json()).resolves.toMatchObject({
      needsPersona: true,
      inquiryId: "inq_1",
    });

    expect(mocks.registerPendingInquiry).toHaveBeenCalledWith(
      "inq_1",
      expect.objectContaining({
        holder: HOLDER,
        issuerId: ISSUER_ID,
        credentialTypes: ["kyc"],
      }),
    );
    expect(mocks.issueAndAuditCredentials).not.toHaveBeenCalled();
  });

  it("merges verified KYC fields into the signed attributes", async () => {
    mocks.resolvePersonaKYC.mockResolvedValue({
      ok: true,
      dob: "1990-01-01",
      countryNumeric: "840",
    });

    const result = await runIssuanceFlow(
      postRequest({ ...kycBody, persona_inquiry_id: "inq_2" }),
      "req-8",
    );

    expect(result.response.status).toBe(200);
    expect(mocks.issueAndAuditCredentials).toHaveBeenCalledWith(
      expect.objectContaining({
        attributes: { date_of_birth: "1990-01-01", country_code: "840" },
      }),
    );
  });

  it("returns 403 when verification is declined", async () => {
    mocks.resolvePersonaKYC.mockResolvedValue({
      ok: false,
      error: "Identity verification was declined",
    });

    const result = await runIssuanceFlow(
      postRequest({ ...kycBody, persona_inquiry_id: "inq_3" }),
      "req-9",
    );

    expect(result.response.status).toBe(403);
    await expect(result.response.json()).resolves.toEqual({
      error: "Identity verification was declined",
    });
    expect(mocks.issueAndAuditCredentials).not.toHaveBeenCalled();
  });
});

describe("runIssuanceFlow — Plaid", () => {
  const fundsBody = {
    credential_types: ["funds"],
    holder: HOLDER,
    issuerId: ISSUER_ID,
    attributes: { balance: "1" },
  };

  it("overwrites a caller-supplied balance with the verified aggregate", async () => {
    mocks.fetchPlaidBalance.mockResolvedValue({ ok: true, balance: 26_500 });

    const result = await runIssuanceFlow(postRequest(fundsBody), "req-10");

    expect(result.response.status).toBe(200);
    expect(mocks.issueAndAuditCredentials).toHaveBeenCalledWith(
      expect.objectContaining({
        attributes: { balance: "26500" },
      }),
    );
  });

  it("propagates a Plaid failure status and code", async () => {
    mocks.fetchPlaidBalance.mockResolvedValue({
      ok: false,
      status: 502,
      code: "PLAID_ERROR",
      error: "Plaid is unavailable",
    });

    const result = await runIssuanceFlow(postRequest(fundsBody), "req-11");

    expect(result.response.status).toBe(502);
    expect(result.outcome).toBe("failure");
    await expect(result.response.json()).resolves.toEqual({
      error: "Plaid is unavailable",
      code: "PLAID_ERROR",
    });
    expect(mocks.issueAndAuditCredentials).not.toHaveBeenCalled();
  });
});
