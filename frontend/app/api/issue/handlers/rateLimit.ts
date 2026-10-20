import type { NextRequest } from "next/server";
import { NextResponse } from "next/server";
import {
  checkLimit,
  extractIp,
  hashForLog,
  tooManyRequestsResponse,
  LIMITS,
} from "@/lib/rate-limit";
import { logger, stripSensitiveFields } from "@/lib/logger";

/**
 * Rate limiting for POST /api/issue.
 *
 * Two dimensions are enforced, in the same order the route has always used:
 *   1. per client IP, before the body is read;
 *   2. per holder wallet, once the body has been parsed.
 *
 * The helpers return the ready-to-send 429 (or `null` when the request is
 * allowed), keeping response construction and PII-free logging out of the
 * dispatcher.
 */

/** Enforce the per-IP issuance limit. Returns a 429 response when throttled. */
export function checkIpRateLimit(req: NextRequest, requestId: string): NextResponse | null {
  const ip = extractIp(req);
  const result = checkLimit(`issue:ip:${ip}`, LIMITS.issuePerIp(), LIMITS.windowMs());
  if (!result.throttled) return null;

  logger.warn(
    stripSensitiveFields({
      event: "rate_limited",
      route: "issue",
      dimension: "ip",
      ipToken: hashForLog(ip),
      requestId,
    }),
  );
  return tooManyRequestsResponse(result.retryAfterMs);
}

/**
 * Enforce the per-wallet issuance limit. The caller passes the already-parsed
 * holder address; a missing holder is not rate limited here because validation
 * will reject the request.
 */
export function checkWalletRateLimit(
  holder: string | undefined,
  requestId: string,
): NextResponse | null {
  if (!holder) return null;

  const result = checkLimit(`issue:wallet:${holder}`, LIMITS.issuePerWallet(), LIMITS.windowMs());
  if (!result.throttled) return null;

  logger.warn(
    stripSensitiveFields({
      event: "rate_limited",
      route: "issue",
      dimension: "wallet",
      walletToken: hashForLog(holder),
      requestId,
    }),
  );
  return tooManyRequestsResponse(result.retryAfterMs);
}
