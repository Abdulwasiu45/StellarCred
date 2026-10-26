// frontend/app/api/_middleware.ts
//
// Shared error boundary and Sentry observability middleware for API routes (#853),
// plus the route-level auth guards.

import { NextResponse, type NextRequest } from "next/server";
import {
  withSentryRouteHandler,
  captureServerException,
  initSentry,
  getSentryClient,
} from "@/lib/monitoring/sentry";
import { authFailure, checkAdminAuth, UNAUTHORIZED, type AuthResult } from "@/lib/auth";
import { resolveTenant, type Tenant } from "@/lib/tenancy";

export { withSentryRouteHandler, captureServerException, initSentry, getSentryClient };

/**
 * Standard API error boundary wrapper.
 * Use around Next.js route handlers:
 *
 * export const POST = withApiErrorBoundary(async (req) => { ... });
 */
export const withApiErrorBoundary = withSentryRouteHandler;

/**
 * Manually captures and formats unexpected API exceptions.
 */
export async function handleApiError(
  req: NextRequest,
  error: unknown,
  status = 500,
): Promise<NextResponse> {
  const requestId = req.headers.get("x-request-id") ?? undefined;
  const eventId = await captureServerException(error, {
    requestId,
    method: req.method,
    path: req.nextUrl.pathname,
    status,
  });

  return Response.json(
    {
      error: "Internal Server Error",
      requestId,
      sentryEventId: eventId,
    },
    { status },
  ) as unknown as NextResponse;
}

// ── Auth guards ──────────────────────────────────────────────────────────────
//
// Routes call a guard first and return its response verbatim when the caller
// is rejected, so the rejection shape is the same everywhere:
//
//   const denied = requireAdmin(req);
//   if (denied) return denied;
//
// Credential parsing and comparison live in lib/auth.ts.

/** A 401 for admin routes when the request lacks a valid admin API key, else null. */
export function requireAdmin(req: NextRequest): NextResponse | null {
  if (checkAdminAuth(req)) return null;
  return NextResponse.json(UNAUTHORIZED, { status: 401 });
}

/**
 * Authenticate the caller's tenant session. Requests without tenant
 * credentials resolve to `null` (the default single-issuer path); a bad,
 * cross-tenant, suspended or revoked key is rejected.
 */
export async function authenticateTenant(req: NextRequest): Promise<AuthResult<Tenant | null>> {
  const result = await resolveTenant(req);
  if (result.error) return authFailure(result.status ?? 401, result.error);
  return { ok: true, value: result.tenant };
}

/** The JSON error response for a rejected {@link AuthResult}, tagged with the request id. */
export function authErrorResponse(
  failure: { status: number; error: string },
  requestId: string,
): NextResponse {
  const res = NextResponse.json({ error: failure.error }, { status: failure.status });
  res.headers.set("x-request-id", requestId);
  return res;
}
