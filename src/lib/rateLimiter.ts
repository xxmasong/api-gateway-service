/**
 * Sliding-window rate limiting backed by Redis.
 *
 * A fixed window ("1000 requests per hour, reset on the hour") lets a caller
 * spend its whole quota in the last second of one window and again in the first
 * second of the next — twice the intended rate across that boundary. This keeps a
 * sorted set of request timestamps per key and trims anything older than the
 * window, so the limit holds over every interval, not just aligned ones.
 */

export interface RateLimitResult {
  allowed: boolean
  limit: number
  remaining: number
  /** Unix ms when the window will have room again. */
  resetAt: number
  /** Seconds to wait, for a Retry-After header. Zero when allowed. */
  retryAfter: number
}

export interface RateLimiterOptions {
  limit: number
  windowMs: number
  /** Namespace prefix, so several limiters can share one Redis instance. */
  prefix?: string
}

/**
 * The subset of a Redis client this limiter needs.
 *
 * Declared structurally rather than importing ioredis, so the limiter can be
 * unit tested against an in-memory fake and swapped for another client. The
 * signatures are deliberately loose where a real client's are overloaded —
 * `multi()` in ioredis has four — because a narrower declaration would not
 * accept the real thing.
 */
export interface RedisLike {
  zremrangebyscore(key: string, min: number | string, max: number | string): Promise<number>
  zcard(key: string): Promise<number>
  zadd(key: string, score: number, member: string): Promise<unknown>
  pexpire(key: string, ms: number): Promise<unknown>
  zrange(key: string, start: number, stop: number): Promise<string[]>
  multi(...args: never[]): RedisPipeline
}

export interface RedisPipeline {
  zremrangebyscore(key: string, min: number | string, max: number | string): RedisPipeline
  zcard(key: string): RedisPipeline
  zrange(key: string, start: number, stop: number): RedisPipeline
  exec(): Promise<unknown>
}

/**
 * Normalise a pipeline result.
 *
 * ioredis resolves `exec()` to `[error, result]` tuples, one per queued command,
 * and raises the first error itself. Other clients and test fakes return the bare
 * values. Accepting both keeps the limiter client-agnostic.
 */
function unwrapPipeline(raw: unknown): unknown[] {
  if (!Array.isArray(raw)) return []

  return raw.map((entry) => {
    if (Array.isArray(entry) && entry.length === 2) {
      const [error, value] = entry as [unknown, unknown]
      if (error instanceof Error) throw error
      return value
    }
    return entry
  })
}

export class RateLimiter {
  private readonly limit: number
  private readonly windowMs: number
  private readonly prefix: string

  constructor(
    private readonly redis: RedisLike,
    options: RateLimiterOptions,
  ) {
    if (options.limit <= 0) throw new Error('limit must be positive')
    if (options.windowMs <= 0) throw new Error('windowMs must be positive')

    this.limit = options.limit
    this.windowMs = options.windowMs
    this.prefix = options.prefix ?? 'ratelimit'
  }

  private keyFor(identifier: string): string {
    return `${this.prefix}:${identifier}`
  }

  async check(identifier: string, now = Date.now()): Promise<RateLimitResult> {
    const key = this.keyFor(identifier)
    const windowStart = now - this.windowMs

    // Read the current state in one round trip: drop expired entries, then count.
    const pipeline = this.redis.multi()
    pipeline.zremrangebyscore(key, 0, windowStart)
    pipeline.zcard(key)
    pipeline.zrange(key, 0, 0)
    const results = unwrapPipeline(await pipeline.exec())

    const count = Number(results[1] ?? 0)
    const oldest = (results[2] as string[] | undefined)?.[0]

    if (count >= this.limit) {
      // The window frees a slot once its oldest entry falls out.
      const oldestTs = oldest ? Number(oldest.split('-')[0]) : now
      const resetAt = oldestTs + this.windowMs
      return {
        allowed: false,
        limit: this.limit,
        remaining: 0,
        resetAt,
        retryAfter: Math.max(1, Math.ceil((resetAt - now) / 1000)),
      }
    }

    // A unique member per request: a bare timestamp would collide for two
    // requests landing in the same millisecond, under-counting the burst.
    const member = `${now}-${Math.random().toString(36).slice(2, 10)}`
    await this.redis.zadd(key, now, member)
    // Let the key expire on its own so idle identifiers do not accumulate.
    await this.redis.pexpire(key, this.windowMs * 2)

    return {
      allowed: true,
      limit: this.limit,
      remaining: this.limit - count - 1,
      resetAt: now + this.windowMs,
      retryAfter: 0,
    }
  }

  async reset(identifier: string): Promise<void> {
    await this.redis.zremrangebyscore(this.keyFor(identifier), 0, Number.MAX_SAFE_INTEGER)
  }
}
