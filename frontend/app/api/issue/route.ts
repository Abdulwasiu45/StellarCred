import { NextRequest, NextResponse } from "next/server";
import { logger, stripSensitiveFields, resolveRequestId } from "@/lib/logger";
import {
  completedIdempotencyRecord,
  idempotencyGetAsync,
  idempotencySetAsync,
  idempotencyInFlightBegin,
  idempotencyInFlightSettle,
  idempotencyInFlightFail,
  isValidIdempotencyKey,
  MAX_KEY_LENGTH_BYTES,
  type IdempotencyRecord,
} from "@/lib/idempotency";
import { checkIpRateLimit } from "./handlers/rateLimit";
import { runIssuanceFlow, type IssuanceFlowResult } from "./handlers/issuanceFlow";

/**
 * POST /api/issue — thin dispatcher.
 *
 * Validation lives in ./handlers/validate.ts, rate limiting in
 * ./handlers/rateLimit.ts, and the provider/signing orchestration in
 * ./handlers/issuanceFlow.ts. This file owns only the request lifecycle:
 * idempotency replay, the per-IP limit, and finalizing the flow's response
 * (request id, idempotency persistence, response logs).
 */
export async function POST(req: NextRequest) {
  const requestId = resolveRequestId(req.headers.get("x-request-id"));

  // ── Idempotency-Key support ────────────────────────────────────────────────
  const rawKey = req.headers.get("Idempotency-Key")?.trim() || undefined;
  const idempotencyKey = rawKey && isValidIdempotencyKey(rawKey) ? rawKey : undefined;
  if (rawKey && !idempotencyKey) {
    logger.warn(
      stripSensitiveFields({
        event: "idempotency_key_rejected",
        requestId,
        reason:
          new TextEncoder().encode(rawKey).length > MAX_KEY_LENGTH_BYTES ? "too_long" : "invalid",
      }),
    );
  }

  if (idempotencyKey) {
    while (true) {
      const record = await idempotencyGetAsync(idempotencyKey);
      if (record) {
        logger.info(stripSensitiveFields({ event: "idempotency_hit", requestId }));
        return replayIdempotencyRecord(record, requestId);
      }

      const inFlight = idempotencyInFlightBegin(idempotencyKey);
      if (!inFlight) break;

      logger.info(stripSensitiveFields({ event: "idempotency_inflight_hit", requestId }));
      try {
        return replayIdempotencyRecord(await inFlight, requestId);
      } catch {
        // A failed leader releases the slot. Rejoining prevents simultaneous
        // retries from all becoming leaders.
      }
    }
  }

  // ── Rate limiting (IP level) ───────────────────────────────────────────────
  const ipLimited = checkIpRateLimit(req, requestId);
  if (ipLimited) {
    if (idempotencyKey) {
      idempotencyInFlightFail(idempotencyKey, new Error("rate limited"));
    }
    return ipLimited;
  }

  const startTime = Date.now();
  try {
    const result = await runIssuanceFlow(req, requestId);
    return await finalizeResponse(result, requestId, idempotencyKey, startTime);
  } catch (e) {
    if (idempotencyKey) idempotencyInFlightFail(idempotencyKey, e);
    throw e;
  }
}

function replayIdempotencyRecord(record: IdempotencyRecord, requestId: string): NextResponse {
  const headers = new Headers({
    "x-request-id": requestId,
    "X-Idempotent": "true",
  });

  if (record.kind === "persona_pending") {
    return NextResponse.json(
      {
        needsPersona: true,
        personaUrl: record.personaUrl,
        inquiryId: record.inquiryId,
      },
      { status: 202, headers },
    );
  }

  headers.set("X-Idempotency-Replay", "redacted");
  return NextResponse.json(
    {
      code: "IDEMPOTENCY_RESPONSE_REDACTED",
      error: "This Idempotency-Key already completed; credential data is not retained for replay.",
    },
    { status: 409, headers },
  );
}

/**
 * Adds the request id, persists the idempotency outcome, and writes the
 * per-credential response log line before the response leaves the process.
 */
async function finalizeResponse(
  result: IssuanceFlowResult,
  requestId: string,
  idempotencyKey: string | undefined,
  startTime: number,
): Promise<NextResponse> {
  const { response, credentialTypes, issuerId, walletAddress, outcome, record } = result;
  const durationMs = Date.now() - startTime;
  response.headers.set("x-request-id", requestId);

  if (idempotencyKey) {
    try {
      const completedRecord =
        record ??
        (response.status === 200
          ? completedIdempotencyRecord(response.status, await response.clone().text())
          : undefined);
      if (completedRecord) {
        await idempotencySetAsync(idempotencyKey, completedRecord);
        idempotencyInFlightSettle(idempotencyKey, completedRecord);
      } else {
        idempotencyInFlightFail(
          idempotencyKey,
          new Error("request did not complete an idempotent operation"),
        );
      }
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
}
