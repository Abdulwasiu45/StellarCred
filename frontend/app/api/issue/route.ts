import { NextRequest, NextResponse } from "next/server";
import { bodyErrorResponse } from "@/lib/request-limits";
import {
  logger,
  stripSensitiveFields,
  resolveRequestId,
} from "@/lib/logger";
import {
  idempotencyGet,
  idempotencySet,
  idempotencyInFlightBegin,
  idempotencyInFlightSettle,
  idempotencyInFlightFail,
  isValidIdempotencyKey,
  MAX_KEY_LENGTH_BYTES,
  type CachedResponse,
} from "@/lib/idempotency";
import {
  normalizeIssueRequest,
  parseIssueBody,
  validateIssueRequest,
  validateIssuerRegistration,
  type ValidationFailure,
} from "./handlers/validate";
import {
  enforceIpRateLimit,
  enforceWalletRateLimit,
} from "./handlers/rateLimit";
import { runIssuanceFlow } from "./handlers/issuanceFlow";

/**
 * POST /api/issue — thin dispatcher.
 *
 * The work is split into focused modules so this file only sequences it:
 *
 *   handlers/validate.ts      parsing, normalisation, field + registry checks
 *   handlers/rateLimit.ts     the per-IP and per-wallet limits
 *   handlers/issuanceFlow.ts  Persona, Plaid, signing, deployment/circuit stamps
 *
 * What stays here is request lifecycle: the idempotency cache (lookup, replay,
 * single-flight join, write-back), the ordering of those steps, and turning an
 * outcome into a response with `x-request-id` on it.
 */
export async function POST(req: NextRequest) {
  const requestId = resolveRequestId(req.headers.get("x-request-id"));

  // ── Idempotency-Key support ────────────────────────────────────────────────
  const rawKey = req.headers.get("Idempotency-Key")?.trim() || undefined;
  const idempotencyKey =
    rawKey && isValidIdempotencyKey(rawKey) ? rawKey : undefined;
  if (rawKey && !idempotencyKey) {
    logger.warn(
      stripSensitiveFields({
        event: "idempotency_key_rejected",
        requestId,
        reason:
          new TextEncoder().encode(rawKey).length > MAX_KEY_LENGTH_BYTES
            ? "too_long"
            : "invalid",
      }),
    );
  }

  if (idempotencyKey) {
    // Cache hit — replay the original response
    const cached = idempotencyGet(idempotencyKey);
    if (cached) {
      logger.info(stripSensitiveFields({ event: "idempotency_hit", requestId }));
      return replayCached(cached, requestId);
    }

    // Concurrent duplicate — await leader
    const inFlight = idempotencyInFlightBegin(idempotencyKey);
    if (inFlight) {
      logger.info(
        stripSensitiveFields({ event: "idempotency_inflight_hit", requestId }),
      );
      try {
        return replayCached(await inFlight, requestId);
      } catch {
        idempotencyInFlightBegin(idempotencyKey);
      }
    }
  }

  // Per-IP limit runs before the body is read, and before the idempotency
  // cache, so a throttled IP never gets its 429 stored and replayed.
  const ipLimited = enforceIpRateLimit(req, requestId);
  if (ipLimited) return ipLimited;

  try {
    return await executeRequest(req, requestId, idempotencyKey);
  } catch (e) {
    if (idempotencyKey) idempotencyInFlightFail(idempotencyKey, e);
    throw e;
  }
}

/** Reconstruct a NextResponse from a cached entry, tagging it as replayed. */
function replayCached(cached: CachedResponse, requestId: string): NextResponse {
  const headers = new Headers(cached.headers as Record<string, string>);
  headers.set("x-request-id", requestId);
  headers.set("X-Idempotent", "true");
  return new NextResponse(cached.body, { status: cached.status, headers });
}

/** Render a validation verdict as the JSON error response callers expect. */
function failureResponse(failure: ValidationFailure): NextResponse {
  return NextResponse.json({ error: failure.error }, { status: failure.status });
}

async function executeRequest(
  req: NextRequest,
  requestId: string,
  idempotencyKey: string | undefined,
) {
  const startTime = Date.now();
  let outcome: "success" | "failure" = "failure";
  let credentialTypes: string[] = [];

  // A body that cannot be read or parsed is answered directly: it is not a
  // verdict on an issuance request, so it is neither cached nor logged as one.
  const parsed = await parseIssueBody(req);
  if (!parsed.ok) {
    const res = bodyErrorResponse(parsed.error);
    res.headers.set("x-request-id", requestId);
    return res;
  }

  const request = normalizeIssueRequest(parsed.body);
  const walletAddress = request.holder;
  const issuerId = request.issuerId;

  const sendResponse = async (response: NextResponse) => {
    const durationMs = Date.now() - startTime;
    response.headers.set("x-request-id", requestId);

    if (idempotencyKey) {
      try {
        const cloned = response.clone();
        const bodyText = await cloned.text();
        const entry: CachedResponse = {
          status: response.status,
          body: bodyText,
          headers: Object.fromEntries(response.headers.entries()),
          createdAt: Date.now(),
        };
        idempotencySet(idempotencyKey, entry);
        idempotencyInFlightSettle(idempotencyKey, entry);
      } catch (e) {
        idempotencyInFlightFail(idempotencyKey, e);
      }
    }

    for (const type of credentialTypes) {
      logger.info(
        stripSensitiveFields({
          event: "response_sent",
          credentialType: type,
          issuerId,
          walletAddress,
          outcome,
          durationMs,
          requestId,
        }),
      );
    }
    return response;
  };

  // ── Per-wallet rate limit ────────────────────────────────────────────────
  if (walletAddress) {
    const walletLimited = enforceWalletRateLimit(walletAddress, requestId);
    if (walletLimited) return sendResponse(walletLimited);
  }

  // `credentialTypes` is set only once the request is past the wallet limit,
  // so a throttled wallet still produces no `response_sent` lines.
  credentialTypes = request.credentialTypes;

  const validated = validateIssueRequest(request, requestId);
  if (!validated.ok) return sendResponse(failureResponse(validated.failure));

  const registrationFailure = await validateIssuerRegistration(
    validated.request.issuerId,
  );
  if (registrationFailure) {
    return sendResponse(failureResponse(registrationFailure));
  }

  const result = await runIssuanceFlow(validated.request, {
    requestId,
    origin: req.nextUrl.origin,
  });

  switch (result.kind) {
    case "persona":
      return sendResponse(
        NextResponse.json(
          {
            needsPersona: true,
            personaUrl: result.personaUrl,
            inquiryId: result.inquiryId,
          },
          { status: 202 },
        ),
      );
    case "issued":
      outcome = "success";
      return sendResponse(
        NextResponse.json({ credentials: result.credentials }),
      );
    case "error":
      return sendResponse(
        NextResponse.json(result.body, { status: result.status }),
      );
  }
}
