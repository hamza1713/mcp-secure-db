import { describe, it, expect, beforeEach } from "vitest";
import { RateLimiter, DEFAULT_RATE_LIMITS } from "../src/security/rate-limiter.js";

describe("Rate Limiter and Query Budgeting (P4)", () => {
  let limiter: RateLimiter;

  beforeEach(() => {
    limiter = new RateLimiter({
      unauthenticated: { maxQueriesPerMinute: 0, maxRowsPerHour: 0 },
      public_viewer: { maxQueriesPerMinute: 2, maxRowsPerHour: 50 },
      analyst: { maxQueriesPerMinute: 5, maxRowsPerHour: 200 },
      admin: { maxQueriesPerMinute: 10, maxRowsPerHour: 1000 },
    });
  });

  it("blocks unauthenticated principals immediately", () => {
    const res = limiter.checkQueryAllowed("anon", "unauthenticated");
    expect(res.allowed).toBe(false);
    expect(res.reason).toContain("no query execution allowance");
  });

  it("permits queries up to tier limit and rejects when exceeded", () => {
    const now = 1000000;
    const principal = "analyst-agent-1";

    // 5 queries allowed
    for (let i = 0; i < 5; i++) {
      const check = limiter.checkQueryAllowed(principal, "analyst", now);
      expect(check.allowed).toBe(true);
      limiter.recordQuery(principal, now);
    }

    // 6th query blocked
    const blocked = limiter.checkQueryAllowed(principal, "analyst", now);
    expect(blocked.allowed).toBe(false);
    expect(blocked.reason).toContain("Rate limit exceeded");
  });

  it("resets query count once the sliding window expires", () => {
    const start = 1000000;
    const principal = "analyst-agent-2";

    // Fill capacity
    for (let i = 0; i < 5; i++) {
      limiter.recordQuery(principal, start);
    }
    expect(limiter.checkQueryAllowed(principal, "analyst", start).allowed).toBe(false);

    // 61 seconds later
    const later = start + 61_000;
    expect(limiter.checkQueryAllowed(principal, "analyst", later).allowed).toBe(true);
  });

  it("enforces row consumption budgets", () => {
    const now = 1000000;
    const principal = "viewer-agent";

    // Consume 40 rows (allowance is 50)
    limiter.recordRows(principal, 40);
    const check1 = limiter.checkQueryAllowed(principal, "public_viewer", now);
    expect(check1.allowed).toBe(true);
    expect(check1.remainingRows).toBe(10);

    // Consume 15 more rows (total 55 > 50)
    limiter.recordRows(principal, 15);
    const check2 = limiter.checkQueryAllowed(principal, "public_viewer", now);
    expect(check2.allowed).toBe(false);
    expect(check2.reason).toContain("Row budget exceeded");
  });
});
