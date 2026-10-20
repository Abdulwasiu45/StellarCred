import { NextRequest, NextResponse } from "next/server";
import { CREDENTIAL_TYPES, type ClaimParams } from "@stellarcred/issuer";
import { readJsonBody, bodyErrorResponse } from "@/lib/request-limits";
import { logger, stripSensitiveFields } from "@/lib/logger";

/**
 * Request parsing and validation for POST /api/issue.
 *
 * The route used to interleave this with rate limiting, provider calls, and
 * signing. Keeping it here makes the accepted wire shapes explicit and lets
 * the validation rules be tested without standing up the whole issuance flow.
 */

export interface IssueRequestBody {
  credential_types?: string[];
  type?: string;
  holder?: string;
  issuerId?: string;
  issuerName?: string;
  expiry?: string;
  attributes?: Record<string, string>;
  attribute?: string;
  claimParams?: ClaimParams;
  persona_inquiry_id?: string;
  returnUrl?: string;
}

export interface ValidatedIssueRequest {
  credentialTypes: string[];
  holder: string;
  issuerId: string;
  issuerName: string;
  expiry: string;
  attributes: Record<string, string>;
  claimParams?: ClaimParams;
  personaInquiryId?: string;
  returnUrl?: string;
}

export type ValidationFailureCode =
  | "credential_types_required"
  | "invalid_credential_type"
  | "holder_required"
  | "issuer_id_required";

export interface IssueValidationFailure {
  ok: false;
  status: 400;
  code: ValidationFailureCode;
  error: string;
  /** Normalized types from the body, so the caller can still log per type. */
  credentialTypes: string[];
  invalidType?: string;
}

export type IssueValidationResult =
  { ok: true; request: ValidatedIssueRequest } | IssueValidationFailure;

export type ParsedIssueRequestBody =
  { ok: true; body: IssueRequestBody } | { ok: false; response: NextResponse };

// readonly CredentialType[] widened to string[] so .includes() accepts any
// user-supplied string during validation, before it's known to be valid.
const VALID_TYPES: readonly string[] = CREDENTIAL_TYPES;

/**
 * Reads and parses the JSON body, returning the standard 400/413 response for
 * malformed or oversized input. The body is normalized to an object so callers
 * never have to guard against `null` or an array payload.
 */
export async function parseIssueRequestBody(req: NextRequest): Promise<ParsedIssueRequestBody> {
  const parsed = await readJsonBody<unknown>(req);
  if (!parsed.ok) {
    return { ok: false, response: bodyErrorResponse(parsed.error) };
  }

  const raw = parsed.body;
  const body =
    raw !== null && typeof raw === "object" && !Array.isArray(raw) ? (raw as IssueRequestBody) : {};

  return { ok: true, body };
}

/**
 * Validates a parsed body and returns either the normalized issuance request
 * or a user-safe 400 failure. Logging mirrors the historical route behavior so
 * dashboards keyed on `request_received` / `validation_result` keep working.
 */
export function validateIssueRequest(
  body: IssueRequestBody,
  requestId?: string,
): IssueValidationResult {
  const credentialTypes = normalizeCredentialTypes(body);
  const issuerId = nonEmptyString(body.issuerId);
  const walletAddress = nonEmptyString(body.holder);

  for (const type of credentialTypes) {
    logger.info(
      stripSensitiveFields({
        event: "request_received",
        credentialType: type,
        issuerId,
        walletAddress,
        requestId,
      }),
    );
  }

  const attributes = normalizeAttributes(body);

  if (credentialTypes.length === 0) {
    return {
      ok: false,
      status: 400,
      code: "credential_types_required",
      error: "credential_types must contain at least one type",
      credentialTypes,
    };
  }

  const invalid = credentialTypes.find((t) => !VALID_TYPES.includes(t));
  if (invalid) {
    for (const type of credentialTypes) {
      logger.info(
        stripSensitiveFields({
          event: "validation_result",
          credentialType: type,
          issuerId,
          walletAddress,
          outcome: "invalid_type",
          requestId,
        }),
      );
    }
    return {
      ok: false,
      status: 400,
      code: "invalid_credential_type",
      error: `Invalid credential type: ${invalid}`,
      credentialTypes,
      invalidType: invalid,
    };
  }

  if (!walletAddress) {
    return {
      ok: false,
      status: 400,
      code: "holder_required",
      error: "holder address is required",
      credentialTypes,
    };
  }

  if (!issuerId) {
    return {
      ok: false,
      status: 400,
      code: "issuer_id_required",
      error: "issuerId is required",
      credentialTypes,
    };
  }

  return {
    ok: true,
    request: {
      credentialTypes,
      holder: walletAddress,
      issuerId,
      issuerName: body.issuerName ?? "StellarCred Authority",
      expiry: body.expiry ?? "90 days",
      attributes,
      claimParams: body.claimParams,
      personaInquiryId: body.persona_inquiry_id,
      returnUrl: body.returnUrl,
    },
  };
}

/** Normalizes the multi-claim shape and the legacy single-type shape. */
export function normalizeCredentialTypes(body: IssueRequestBody): string[] {
  if (Array.isArray(body.credential_types)) {
    return body.credential_types as string[];
  }
  return body.type ? [body.type] : [];
}

/**
 * Copies caller attributes and backfills the legacy single-attribute field
 * onto its type-specific key. Explicit `attributes` always win.
 */
export function normalizeAttributes(body: IssueRequestBody): Record<string, string> {
  const attributes: Record<string, string> = {
    ...(body.attributes && typeof body.attributes === "object" ? body.attributes : {}),
  };
  if (body.attribute !== undefined && body.type) {
    if (body.type === "age") attributes.date_of_birth ??= body.attribute;
    else if (body.type === "income") attributes.income ??= body.attribute;
    else if (body.type === "jurisdiction") attributes.country_code ??= body.attribute;
    else if (body.type === "employment") attributes.seniority ??= body.attribute;
  }
  return attributes;
}

function nonEmptyString(value: unknown): string | undefined {
  return typeof value === "string" && value.length > 0 ? value : undefined;
}
