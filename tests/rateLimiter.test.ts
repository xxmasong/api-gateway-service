import { beforeEach, describe, expect, it } from 'vitest'

import { RateLimiter, type RedisLike, type RedisPipeline } from '../src/lib/rateLimiter'

/** An in-memory stand-in for the sorted-set commands the limiter uses. */
class FakeRedis implements RedisLike {
  private sets = new Map<string, Array<{ score: number; member: string }>>()
  private expiries = new Map<string, number>()

  private entries(key: string) {
    if (!this.sets.has(key)) this.sets.set(key, [])
    return this.sets.get(key)!
  }

  async zremrangebyscore(key: string, min: number | string, max: number | string): Promise<number> {
    const [lo, hi] = [Number(min), Number(max)]
    const list = this.entries(key)
    const before = list.length
    const kept = list.filter((e) => e.score < lo || e.score > hi)
    this.sets.set(key, kept)
    return before - kept.length
  }

  async zcard(key: string): Promise<number> {
    return this.entries(key).length
  }

  async zadd(key: string, score: number, member: string): Promise<number> {
    this.entries(key).push({ score, member })
    this.entries(key).sort((a, b) => a.score - b.score)
    return 1
  }

  async pexpire(key: string, ms: number): Promise<number> {
    this.expiries.set(key, ms)
    return 1
  }

  async zrange(key: string, start: number, stop: number): Promise<string[]> {
    const list = [...this.entries(key)].sort((a, b) => a.score - b.score)
    const end = stop < 0 ? list.length + stop + 1 : stop + 1
    return list.slice(start, end).map((e) => e.member)
  }

  expiryFor(key: string): number | undefined {
    return this.expiries.get(key)
  }

  multi(): RedisPipeline {
    const ops: Array<() => Promise<unknown>> = []
    const pipeline: RedisPipeline = {
      zremrangebyscore: (key, min, max) => {
        ops.push(() => this.zremrangebyscore(key, min, max))
        return pipeline
      },
      zcard: (key) => {
        ops.push(() => this.zcard(key))
        return pipeline
      },
      zrange: (key, start, stop) => {
        ops.push(() => this.zrange(key, start, stop))
        return pipeline
      },
      exec: async () => {
        const out: unknown[] = []
        for (const op of ops) out.push(await op())
        return out
      },
    }
    return pipeline
  }
}

describe('RateLimiter', () => {
  let redis: FakeRedis

  beforeEach(() => {
    redis = new FakeRedis()
  })

  it('rejects an invalid configuration', () => {
    expect(() => new RateLimiter(redis, { limit: 0, windowMs: 1000 })).toThrow(/limit/)
    expect(() => new RateLimiter(redis, { limit: 5, windowMs: 0 })).toThrow(/windowMs/)
  })

  it('allows requests up to the limit', async () => {
    const limiter = new RateLimiter(redis, { limit: 3, windowMs: 60_000 })
    const now = 1_000_000

    for (let i = 0; i < 3; i += 1) {
      const result = await limiter.check('user-1', now + i)
      expect(result.allowed).toBe(true)
    }
  })

  it('counts down remaining', async () => {
    const limiter = new RateLimiter(redis, { limit: 3, windowMs: 60_000 })
    const now = 1_000_000

    expect((await limiter.check('u', now)).remaining).toBe(2)
    expect((await limiter.check('u', now + 1)).remaining).toBe(1)
    expect((await limiter.check('u', now + 2)).remaining).toBe(0)
  })

  it('blocks the request past the limit', async () => {
    const limiter = new RateLimiter(redis, { limit: 2, windowMs: 60_000 })
    const now = 1_000_000

    await limiter.check('u', now)
    await limiter.check('u', now + 1)
    const blocked = await limiter.check('u', now + 2)

    expect(blocked.allowed).toBe(false)
    expect(blocked.remaining).toBe(0)
    expect(blocked.retryAfter).toBeGreaterThan(0)
  })

  it('tracks identifiers independently', async () => {
    const limiter = new RateLimiter(redis, { limit: 1, windowMs: 60_000 })
    const now = 1_000_000

    expect((await limiter.check('alice', now)).allowed).toBe(true)
    expect((await limiter.check('bob', now)).allowed).toBe(true)
    expect((await limiter.check('alice', now + 1)).allowed).toBe(false)
  })

  it('frees capacity as the window slides, not on a fixed reset', async () => {
    const limiter = new RateLimiter(redis, { limit: 2, windowMs: 1000 })
    const start = 1_000_000

    await limiter.check('u', start)
    await limiter.check('u', start + 500)
    expect((await limiter.check('u', start + 600)).allowed).toBe(false)

    // The first entry ages out at start+1000, so one slot opens then — rather
    // than the whole quota resetting at an aligned boundary.
    expect((await limiter.check('u', start + 1001)).allowed).toBe(true)
    expect((await limiter.check('u', start + 1002)).allowed).toBe(false)
  })

  it('does not permit a double burst across a window boundary', async () => {
    const limiter = new RateLimiter(redis, { limit: 5, windowMs: 1000 })
    const start = 1_000_000

    // Spend the quota at the end of the first notional window.
    for (let i = 0; i < 5; i += 1) {
      expect((await limiter.check('u', start + 900 + i)).allowed).toBe(true)
    }
    // Immediately after a fixed window would have reset, the sliding window
    // still remembers those five requests.
    expect((await limiter.check('u', start + 1000)).allowed).toBe(false)
  })

  it('reports resetAt based on the oldest entry', async () => {
    const limiter = new RateLimiter(redis, { limit: 1, windowMs: 5000 })
    const start = 2_000_000

    await limiter.check('u', start)
    const blocked = await limiter.check('u', start + 100)

    expect(blocked.resetAt).toBe(start + 5000)
    expect(blocked.retryAfter).toBe(5)
  })

  it('distinguishes requests in the same millisecond', async () => {
    const limiter = new RateLimiter(redis, { limit: 3, windowMs: 60_000 })
    const now = 1_000_000

    await limiter.check('u', now)
    await limiter.check('u', now)
    const third = await limiter.check('u', now)

    // A bare timestamp as the member would collide and under-count the burst.
    expect(third.allowed).toBe(true)
    expect(third.remaining).toBe(0)
    expect(await redis.zcard('ratelimit:u')).toBe(3)
  })

  it('sets a TTL so idle identifiers are reclaimed', async () => {
    const limiter = new RateLimiter(redis, { limit: 5, windowMs: 1000 })
    await limiter.check('u', 1_000_000)
    expect(redis.expiryFor('ratelimit:u')).toBe(2000)
  })

  it('namespaces keys by prefix', async () => {
    const limiter = new RateLimiter(redis, { limit: 5, windowMs: 1000, prefix: 'login' })
    await limiter.check('u', 1_000_000)
    expect(await redis.zcard('login:u')).toBe(1)
    expect(await redis.zcard('ratelimit:u')).toBe(0)
  })

  it('clears a key on reset', async () => {
    const limiter = new RateLimiter(redis, { limit: 1, windowMs: 60_000 })
    const now = 1_000_000

    await limiter.check('u', now)
    expect((await limiter.check('u', now + 1)).allowed).toBe(false)

    await limiter.reset('u')
    expect((await limiter.check('u', now + 2)).allowed).toBe(true)
  })
})

describe('ioredis pipeline compatibility', () => {
  /**
   * ioredis resolves exec() to [error, result] tuples rather than bare values.
   * This wraps the plain fake's results the same way to prove the limiter reads
   * either shape.
   */
  function tupleRedis(base: FakeRedis): RedisLike {
    return {
      ...base,
      zremrangebyscore: (k, a, b) => base.zremrangebyscore(k, a, b),
      zcard: (k) => base.zcard(k),
      zadd: (k, s, m) => base.zadd(k, s, m),
      pexpire: (k, ms) => base.pexpire(k, ms),
      zrange: (k, a, b) => base.zrange(k, a, b),
      multi: () => {
        const inner = base.multi()
        return {
          zremrangebyscore: (k, a, b) => inner.zremrangebyscore(k, a, b),
          zcard: (k) => inner.zcard(k),
          zrange: (k, a, b) => inner.zrange(k, a, b),
          exec: async () => {
            const plain = (await inner.exec()) as unknown[]
            return plain.map((value) => [null, value])
          },
        }
      },
    }
  }

  it('reads results out of [error, result] tuples', async () => {
    const limiter = new RateLimiter(tupleRedis(new FakeRedis()), { limit: 2, windowMs: 60_000 })
    const now = 1_000_000

    expect((await limiter.check('u', now)).allowed).toBe(true)
    expect((await limiter.check('u', now + 1)).allowed).toBe(true)
    expect((await limiter.check('u', now + 2)).allowed).toBe(false)
  })
})
