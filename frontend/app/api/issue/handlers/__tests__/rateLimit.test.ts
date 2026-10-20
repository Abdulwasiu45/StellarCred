import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { NextRequest } from "next/server";
import { checkIpRateLimit, checkWalletRateLimit } from "../rateLimit";
import { rateLimitClear } from "@/lib/rate-limit";

const WALLET = "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF";
const OTHER_WALLET = "GBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBHF2";

const ENV_KEYS = ["RATE_LIMIT_ISSUE_IP", "RATE_LIMIT_ISSUE_WALLET"] as const;
const savedEnv: Record<string, string | undefined> = {};

beforeEach(() => {
  for (const key of ENV_KEYS) savedEnv[key] = process.env[key];
  delete process.env.RATE_LIMIT_ISSUE_IP;
  delete process.env.RATE_LIMIT_ISSUE_WALLET;
  rateLimitClear();
});

afterEach(() => {
  for (const key of ENV_KEYS) {
    if (savedEnv[key] === undefined) delete process.env[key];
    else process.env[key] = savedEnv[key];
  }
  rateLimitClear();
});

function request(ip = "203.0.113.10"): NextRequest {
  return new NextRequest("http://localhost/api/issue", {
    method: "POST",
    headers: { "x-forwarded-for": ip },
  });
}

describe("checkIpRateLimit", () => {
  it("allows requests under the configured IP limit", () => {
    process.env.RATE_LIMIT_ISSUE_IP = "2";

    expect(checkIpRateLimit(request(), "req-1")).toBeNull();
    expect(checkIpRateLimit(request(), "req-2")).toBeNull();
  });

  it("returns a 429 with Retry-After once the IP limit is exceeded", async () => {
    process.env.RATE_LIMIT_ISSUE_IP = "1";

    expect(checkIpRateLimit(request(), "req-1")).toBeNull();
    const limited = checkIpRateLimit(request(), "req-2");

    expect(limited).not.toBeNull();
    expect(limited?.status).toBe(429);
    expect(limited?.headers.get("Retry-After")).toBeTruthy();
    await expect(limited?.json()).resolves.toMatchObject({
      code: "rate_limited",
    });
  });

  it("tracks separate IPs independently", () => {
    process.env.RATE_LIMIT_ISSUE_IP = "1";

    expect(checkIpRateLimit(request("203.0.113.1"), "req-1")).toBeNull();
    expect(checkIpRateLimit(request("203.0.113.2"), "req-2")).toBeNull();
    expect(checkIpRateLimit(request("203.0.113.1"), "req-3")).not.toBeNull();
  });
});

describe("checkWalletRateLimit", () => {
  it("does not rate limit a request with no holder", () => {
    process.env.RATE_LIMIT_ISSUE_WALLET = "1";

    expect(checkWalletRateLimit(undefined, "req-1")).toBeNull();
  });

  it("allows requests under the configured wallet limit", () => {
    process.env.RATE_LIMIT_ISSUE_WALLET = "2";

    expect(checkWalletRateLimit(WALLET, "req-1")).toBeNull();
    expect(checkWalletRateLimit(WALLET, "req-2")).toBeNull();
  });

  it("returns a 429 once the wallet limit is exceeded", async () => {
    process.env.RATE_LIMIT_ISSUE_WALLET = "1";

    expect(checkWalletRateLimit(WALLET, "req-1")).toBeNull();
    const limited = checkWalletRateLimit(WALLET, "req-2");

    expect(limited).not.toBeNull();
    expect(limited?.status).toBe(429);
    await expect(limited?.json()).resolves.toMatchObject({
      code: "rate_limited",
    });
  });

  it("tracks separate wallets independently", () => {
    process.env.RATE_LIMIT_ISSUE_WALLET = "1";

    expect(checkWalletRateLimit(WALLET, "req-1")).toBeNull();
    expect(checkWalletRateLimit(OTHER_WALLET, "req-2")).toBeNull();
    expect(checkWalletRateLimit(WALLET, "req-3")).not.toBeNull();
  });
});
