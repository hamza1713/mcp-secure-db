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

interface PrincipalState {
  queryTimestamps: number[];
  rowsConsumed: number;
  windowStart: number;
}

/**
 * In-memory sliding-window rate limiter and row-budget accounting per principal.
 * Limits query frequency and cumulative row egress to bound exfiltration and resource abuse.
 */
export class RateLimiter {
  private states = new Map<string, PrincipalState>();
  private readonly limits: Record<UserRole, RateLimitTierConfig>;
  private readonly windowDurationMs: number;
  private readonly rowWindowDurationMs: number;

  constructor(
    limits: Record<UserRole, RateLimitTierConfig> = DEFAULT_RATE_LIMITS,
    windowDurationMs = 60_000,
    rowWindowDurationMs = 3_600_000
  ) {
    this.limits = limits;
    this.windowDurationMs = windowDurationMs;
    this.rowWindowDurationMs = rowWindowDurationMs;
  }

  public checkQueryAllowed(
    principal: string,
    role: UserRole,
    now = Date.now()
  ): {
    allowed: boolean;
    reason?: string;
    remainingQueries?: number;
    remainingRows?: number;
  } {
    const tier = this.limits[role] ?? this.limits.unauthenticated;
    if (tier.maxQueriesPerMinute === 0) {
      return {
        allowed: false,
        reason: `Role '${role}' has no query execution allowance.`,
      };
    }

    let state = this.states.get(principal);
    if (!state) {
      state = {
        queryTimestamps: [],
        rowsConsumed: 0,
        windowStart: now,
      };
      this.states.set(principal, state);
    }

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

    return {
      allowed: true,
      remainingQueries:
        tier.maxQueriesPerMinute - state.queryTimestamps.length - 1,
      remainingRows: tier.maxRowsPerHour - state.rowsConsumed,
    };
  }

  public recordQuery(principal: string, now = Date.now()): void {
    let state = this.states.get(principal);
    if (!state) {
      state = {
        queryTimestamps: [],
        rowsConsumed: 0,
        windowStart: now,
      };
      this.states.set(principal, state);
    }
    state.queryTimestamps.push(now);
  }

  public recordRows(principal: string, count: number, now = Date.now()): void {
    let state = this.states.get(principal);
    if (!state) {
      state = {
        queryTimestamps: [],
        rowsConsumed: 0,
        windowStart: now,
      };
      this.states.set(principal, state);
    }
    state.rowsConsumed += count;
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
