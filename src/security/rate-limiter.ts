import { UserRole } from "../types.js";

export class RateLimitExceededError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "RateLimitExceededError";
  }
}

export interface RateLimitTierConfig {
  maxQueriesPerMinute: number;
  maxRowsPerHour: number;
}

export const DEFAULT_RATE_LIMITS: Record<UserRole, RateLimitTierConfig> = {
  unauthenticated: {
    maxQueriesPerMinute: 0,
    maxRowsPerHour: 0,
  },
  public_viewer: {
    maxQueriesPerMinute: 30,
    maxRowsPerHour: 2000,
  },
  analyst: {
    maxQueriesPerMinute: 60,
    maxRowsPerHour: 10000,
  },
  admin: {
    maxQueriesPerMinute: 120,
    maxRowsPerHour: 50000,
  },
};

export const DEFAULT_VALIDATION_RATE_LIMITS: Record<
  UserRole,
  RateLimitTierConfig
> = {
  unauthenticated: {
    maxQueriesPerMinute: 0,
    maxRowsPerHour: 0,
  },
  public_viewer: {
    maxQueriesPerMinute: 60,
    maxRowsPerHour: 100000,
  },
  analyst: {
    maxQueriesPerMinute: 120,
    maxRowsPerHour: 100000,
  },
  admin: {
    maxQueriesPerMinute: 240,
    maxRowsPerHour: 100000,
  },
};

export interface RateLimitCheckResult {
  allowed: boolean;
  reason?: string;
  remainingQueries?: number;
  remainingRows?: number;
}

interface PrincipalState {
  queryTimestamps: number[];
  rowsConsumed: number;
  windowStart: number;
  lastSeen: number;
}

/**
 * In-memory sliding-window rate limiter and row-budget accounting per principal.
 * Uses atomic check-and-consume (`consumeQuerySlot`) to close check-then-act races
 * and ensure failed, blocked, or timed-out queries still consume request quota.
 */
export class RateLimiter {
  private states = new Map<string, PrincipalState>();
  private readonly limits: Record<UserRole, RateLimitTierConfig>;
  private readonly windowDurationMs: number;
  private readonly rowWindowDurationMs: number;
  private readonly maxTrackedPrincipals: number;

  constructor(
    limits: Record<UserRole, RateLimitTierConfig> = DEFAULT_RATE_LIMITS,
    windowDurationMs = 60_000,
    rowWindowDurationMs = 3_600_000,
    maxTrackedPrincipals = 10_000
  ) {
    this.limits = limits;
    this.windowDurationMs = windowDurationMs;
    this.rowWindowDurationMs = rowWindowDurationMs;
    this.maxTrackedPrincipals = maxTrackedPrincipals;
  }

  private evictStalePrincipals(now: number): void {
    if (this.states.size <= this.maxTrackedPrincipals) {
      return;
    }

    const queryCutoff = now - this.windowDurationMs;
    for (const [key, st] of this.states.entries()) {
      const noRecentQueries =
        st.queryTimestamps.length === 0 ||
        st.queryTimestamps[st.queryTimestamps.length - 1] <= queryCutoff;
      const rowWindowExpired = now - st.windowStart > this.rowWindowDurationMs;
      if (noRecentQueries && rowWindowExpired) {
        this.states.delete(key);
      }
    }

    // If still above bound, evict least-recently-seen entries
    if (this.states.size > this.maxTrackedPrincipals) {
      const sorted = [...this.states.entries()].sort(
        (a, b) => a[1].lastSeen - b[1].lastSeen
      );
      const toRemove = this.states.size - this.maxTrackedPrincipals;
      for (let i = 0; i < toRemove; i++) {
        this.states.delete(sorted[i][0]);
      }
    }
  }

  private getOrCreateState(principal: string, now: number): PrincipalState {
    let state = this.states.get(principal);
    if (!state) {
      this.evictStalePrincipals(now);
      state = {
        queryTimestamps: [],
        rowsConsumed: 0,
        windowStart: now,
        lastSeen: now,
      };
      this.states.set(principal, state);
    }
    state.lastSeen = now;
    return state;
  }

  private evaluateState(
    principal: string,
    role: UserRole,
    now: number,
    consume: boolean
  ): RateLimitCheckResult {
    const tier = Object.hasOwn(this.limits, role)
      ? this.limits[role]
      : this.limits.unauthenticated;
    if (tier.maxQueriesPerMinute === 0) {
      return {
        allowed: false,
        reason: `Role '${role}' has no query execution allowance.`,
      };
    }

    const state = this.getOrCreateState(principal, now);

    // Clean query timestamps older than sliding query window
    const cutoff = now - this.windowDurationMs;
    state.queryTimestamps = state.queryTimestamps.filter((ts) => ts > cutoff);

    // Reset row consumption if row window has expired
    if (now - state.windowStart > this.rowWindowDurationMs) {
      state.rowsConsumed = 0;
      state.windowStart = now;
    }

    if (state.queryTimestamps.length >= tier.maxQueriesPerMinute) {
      return {
        allowed: false,
        reason: `Rate limit exceeded for principal '${principal}': maximum ${tier.maxQueriesPerMinute} queries per minute.`,
        remainingQueries: 0,
        remainingRows: Math.max(0, tier.maxRowsPerHour - state.rowsConsumed),
      };
    }

    if (state.rowsConsumed >= tier.maxRowsPerHour) {
      return {
        allowed: false,
        reason: `Row budget exceeded for principal '${principal}': consumed ${state.rowsConsumed} of ${tier.maxRowsPerHour} rows per hour.`,
        remainingQueries:
          tier.maxQueriesPerMinute - state.queryTimestamps.length,
        remainingRows: 0,
      };
    }

    if (consume) {
      state.queryTimestamps.push(now);
    }

    const usedCount = state.queryTimestamps.length;
    return {
      allowed: true,
      remainingQueries: Math.max(
        0,
        tier.maxQueriesPerMinute - (consume ? usedCount : usedCount + 1)
      ),
      remainingRows: Math.max(0, tier.maxRowsPerHour - state.rowsConsumed),
    };
  }

  public checkQueryAllowed(
    principal: string,
    role: UserRole,
    now = Date.now()
  ): RateLimitCheckResult {
    return this.evaluateState(principal, role, now, false);
  }

  /**
   * Atomically verifies quota and consumes one query slot up front so concurrent
   * calls cannot race past the limit and failed/timed-out queries still count.
   */
  public consumeQuerySlot(
    principal: string,
    role: UserRole,
    now = Date.now()
  ): RateLimitCheckResult {
    return this.evaluateState(principal, role, now, true);
  }

  public recordQuery(principal: string, now = Date.now()): void {
    const state = this.getOrCreateState(principal, now);
    state.queryTimestamps.push(now);
  }

  public recordRows(principal: string, count: number, now = Date.now()): void {
    const state = this.getOrCreateState(principal, now);
    state.rowsConsumed += Math.max(0, count);
  }

  public getTrackedPrincipalCount(): number {
    return this.states.size;
  }

  public reset(principal?: string): void {
    if (principal) {
      this.states.delete(principal);
    } else {
      this.states.clear();
    }
  }
}

export const defaultRateLimiter = new RateLimiter();
export const validationRateLimiter = new RateLimiter(
  DEFAULT_VALIDATION_RATE_LIMITS
);
