// @vitest-environment node
//
// @stellarcred/issuer refuses to load when `window` exists (server-only guard),
// so this suite runs under Node rather than the workspace-default jsdom.

import { describe, it, expect } from "vitest";
import { NextRequest } from "next/server";
import {
  normalizeAttributes,
  normalizeCredentialTypes,
  parseIssueRequestBody,
  validateIssueRequest,
  type IssueRequestBody,
} from "../validate";

const HOLDER = "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF";
const ISSUER_ID = "GBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBHF2";

function body(overrides: Partial<IssueRequestBody> = {}): IssueRequestBody {
  return {
    credential_types: ["age"],
    holder: HOLDER,
    issuerId: ISSUER_ID,
    attributes: { date_of_birth: "1995-06-15" },
    ...overrides,
  };
}

describe("validateIssueRequest", () => {
  it("normalizes the multi-claim shape and applies defaults", () => {
    const result = validateIssueRequest(body({ credential_types: ["age", "income"] }));

    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.request).toEqual({
      credentialTypes: ["age", "income"],
      holder: HOLDER,
      issuerId: ISSUER_ID,
      issuerName: "StellarCred Authority",
      expiry: "90 days",
      attributes: { date_of_birth: "1995-06-15" },
      claimParams: undefined,
      personaInquiryId: undefined,
      returnUrl: undefined,
    });
  });

  it("accepts the legacy single-type shape and backfills its attribute", () => {
    const result = validateIssueRequest({
      type: "age",
      attribute: "1995-06-15",
      holder: HOLDER,
      issuerId: ISSUER_ID,
    });

    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.request.credentialTypes).toEqual(["age"]);
    expect(result.request.attributes).toEqual({ date_of_birth: "1995-06-15" });
  });

  it("lets explicit attributes win over the legacy attribute field", () => {
    const result = validateIssueRequest({
      type: "age",
      attribute: "legacy-value",
      holder: HOLDER,
      issuerId: ISSUER_ID,
      attributes: { date_of_birth: "1990-01-01" },
    });

    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.request.attributes.date_of_birth).toBe("1990-01-01");
  });

  it("rejects a request with no credential types", () => {
    const result = validateIssueRequest({
      holder: HOLDER,
      issuerId: ISSUER_ID,
    });

    expect(result).toMatchObject({
      ok: false,
      status: 400,
      code: "credential_types_required",
      error: "credential_types must contain at least one type",
    });
  });

  it("rejects an unknown credential type and reports which one", () => {
    const result = validateIssueRequest(body({ credential_types: ["age", "not-a-real-type"] }));

    expect(result).toMatchObject({
      ok: false,
      status: 400,
      code: "invalid_credential_type",
      invalidType: "not-a-real-type",
      error: "Invalid credential type: not-a-real-type",
    });
    if (result.ok) return;
    expect(result.credentialTypes).toEqual(["age", "not-a-real-type"]);
  });

  it("rejects a missing holder address", () => {
    const result = validateIssueRequest(body({ holder: undefined }));

    expect(result).toMatchObject({
      ok: false,
      status: 400,
      code: "holder_required",
      error: "holder address is required",
    });
  });

  it("rejects a missing issuerId", () => {
    const result = validateIssueRequest(body({ issuerId: undefined }));

    expect(result).toMatchObject({
      ok: false,
      status: 400,
      code: "issuer_id_required",
      error: "issuerId is required",
    });
  });

  it("carries Persona resume context through validation", () => {
    const result = validateIssueRequest(
      body({
        credential_types: ["kyc"],
        persona_inquiry_id: "inq_123",
        returnUrl: "https://proto.example/callback",
      }),
    );

    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.request.personaInquiryId).toBe("inq_123");
    expect(result.request.returnUrl).toBe("https://proto.example/callback");
  });
});

describe("normalizeCredentialTypes", () => {
  it("prefers credential_types over type", () => {
    expect(normalizeCredentialTypes({ credential_types: ["kyc"], type: "age" })).toEqual(["kyc"]);
  });

  it("falls back to the legacy type field", () => {
    expect(normalizeCredentialTypes({ type: "age" })).toEqual(["age"]);
  });

  it("returns an empty list when neither field is present", () => {
    expect(normalizeCredentialTypes({})).toEqual([]);
  });
});

describe("normalizeAttributes", () => {
  it("maps each legacy attribute to its type-specific key", () => {
    expect(normalizeAttributes({ type: "income", attribute: "150000" })).toEqual({
      income: "150000",
    });
    expect(normalizeAttributes({ type: "jurisdiction", attribute: "840" })).toEqual({
      country_code: "840",
    });
    expect(normalizeAttributes({ type: "employment", attribute: "5" })).toEqual({
      seniority: "5",
    });
  });

  it("does not copy attributes onto a key for kyc", () => {
    expect(normalizeAttributes({ type: "kyc", attribute: "ignored" })).toEqual({});
  });
});

describe("parseIssueRequestBody", () => {
  it("parses a JSON object body", async () => {
    const result = await parseIssueRequestBody(postRequest(body()));

    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.body.holder).toBe(HOLDER);
  });

  it("returns a 400 response for malformed JSON", async () => {
    const result = await parseIssueRequestBody(
      new NextRequest("http://localhost/api/issue", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: "{not-json",
      }),
    );

    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.response.status).toBe(400);
    await expect(result.response.json()).resolves.toMatchObject({
      code: "invalid_json",
    });
  });

  it("normalizes a non-object JSON body to an empty object", async () => {
    const result = await parseIssueRequestBody(
      new NextRequest("http://localhost/api/issue", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: "[]",
      }),
    );

    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.body).toEqual({});
  });
});

function postRequest(payload: unknown): NextRequest {
  return new NextRequest("http://localhost/api/issue", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
}
