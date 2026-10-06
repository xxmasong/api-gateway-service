import { SignJWT } from 'jose'
import request from 'supertest'
import { beforeEach, describe, expect, it } from 'vitest'

import { createApp } from '../src/app'
import { RateLimiter, type RedisLike, type RedisPipeline } from '../src/lib/rateLimiter'

const SECRET = new TextEncoder().encode('test-secret-at-least-32-bytes-long!!')

class FakeRedis implements RedisLike {
  private sets = new Map<string, Array<{ score: number; member: string }>>()

  private entries(key: string) {
    if (!this.sets.has(key)) this.sets.set(key, [])
    return this.sets.get(key)!
  }

  async zremrangebyscore(key: string, min: number | string, max: number | string) {
    const [lo, hi] = [Number(min), Number(max)]
    const list = this.entries(key)
    const before = list.length
    this.sets.set(
      key,
      list.filter((e) => e.score < lo || e.score > hi),
    )
    return before - this.entries(key).length
  }
  async zcard(key: string) {
    return this.entries(key).length
  }
  async zadd(key: string, score: number, member: string) {
    this.entries(key).push({ score, member })
    return 1
  }
  async pexpire() {
    return 1
  }
  async zrange(key: string, start: number, stop: number) {
    const list = [...this.entries(key)].sort((a, b) => a.score - b.score)
    const end = stop < 0 ? list.length + stop + 1 : stop + 1
    return list.slice(start, end).map((e) => e.member)
  }
  multi(): RedisPipeline {
    const ops: Array<() => Promise<unknown>> = []
    const p: RedisPipeline = {
      zremrangebyscore: (k, a, b) => (ops.push(() => this.zremrangebyscore(k, a, b)), p),
      zcard: (k) => (ops.push(() => this.zcard(k)), p),
      zrange: (k, a, b) => (ops.push(() => this.zrange(k, a, b)), p),
      exec: async () => {
        const out: unknown[] = []
        for (const op of ops) out.push(await op())
        return out
      },
    }
    return p
  }
}

/** A limiter whose backing store always fails, to exercise the fail-open path. */
const brokenRedis: RedisLike = {
  zremrangebyscore: async () => {
    throw new Error('redis down')
  },
  zcard: async () => {
    throw new Error('redis down')
  },
  zadd: async () => {
    throw new Error('redis down')
  },
  pexpire: async () => {
    throw new Error('redis down')
  },
  zrange: async () => {
    throw new Error('redis down')
  },
  multi: () => {
    throw new Error('redis down')
  },
}

async function signToken(sub: string, { expired = false } = {}) {
  const now = Math.floor(Date.now() / 1000)
  return new SignJWT({ sub })
    .setProtectedHeader({ alg: 'HS256' })
    .setSubject(sub)
    .setIssuedAt(expired ? now - 7200 : now)
    .setExpirationTime(expired ? now - 3600 : now + 3600)
    .sign(SECRET)
}

function buildApp(overrides: { limit?: number; broken?: boolean } = {}) {
  const redis = overrides.broken ? brokenRedis : new FakeRedis()
  return createApp({
    auth: { secret: SECRET },
    globalLimiter: new RateLimiter(redis, {
      limit: overrides.limit ?? 100,
      windowMs: 60_000,
      prefix: 'global',
    }),
    loginLimiter: new RateLimiter(redis, { limit: 3, windowMs: 60_000, prefix: 'login' }),
  })
}

describe('gateway', () => {
  let app: ReturnType<typeof buildApp>

  beforeEach(() => {
    app = buildApp()
  })

  it('serves health without authentication', async () => {
    const res = await request(app).get('/health')
    expect(res.status).toBe(200)
    expect(res.body).toEqual({ status: 'ok' })
  })

  it('rejects /me without a token', async () => {
    const res = await request(app).get('/me')
    expect(res.status).toBe(401)
    expect(res.body.error).toBe('unauthorized')
  })

  it('accepts a valid token', async () => {
    const token = await signToken('user-42')
    const res = await request(app).get('/me').set('Authorization', `Bearer ${token}`)

    expect(res.status).toBe(200)
    expect(res.body.userId).toBe('user-42')
  })

  it('accepts a lowercase bearer scheme', async () => {
    const token = await signToken('user-42')
    const res = await request(app).get('/me').set('Authorization', `bearer ${token}`)
    expect(res.status).toBe(200)
  })

  it('rejects a malformed Authorization header', async () => {
    const res = await request(app).get('/me').set('Authorization', 'Basic abc123')
    expect(res.status).toBe(401)
  })

  it('rejects an expired token', async () => {
    const token = await signToken('user-42', { expired: true })
    const res = await request(app).get('/me').set('Authorization', `Bearer ${token}`)
    expect(res.status).toBe(401)
  })

  it('rejects a token signed with the wrong key', async () => {
    const wrong = new TextEncoder().encode('another-secret-at-least-32-bytes!!!!')
    const token = await new SignJWT({ sub: 'user-42' })
      .setProtectedHeader({ alg: 'HS256' })
      .setSubject('user-42')
      .setExpirationTime('1h')
      .sign(wrong)

    const res = await request(app).get('/me').set('Authorization', `Bearer ${token}`)
    expect(res.status).toBe(401)
  })

  it('does not reveal why a token failed', async () => {
    const expired = await signToken('user-42', { expired: true })
    const expiredRes = await request(app).get('/me').set('Authorization', `Bearer ${expired}`)
    const garbageRes = await request(app).get('/me').set('Authorization', 'Bearer not.a.jwt')

    // An attacker must not learn which of the two failure modes occurred.
    expect(expiredRes.body.message).toBe(garbageRes.body.message)
  })

  it('sets RateLimit headers', async () => {
    const res = await request(app).get('/health')
    expect(res.status).toBe(200)

    const limited = await request(app).get('/me')
    expect(limited.headers['ratelimit-limit']).toBe('100')
    expect(limited.headers['ratelimit-remaining']).toBeDefined()
  })

  it('returns 429 with Retry-After past the limit', async () => {
    app = buildApp({ limit: 2 })

    await request(app).get('/me')
    await request(app).get('/me')
    const blocked = await request(app).get('/me')

    expect(blocked.status).toBe(429)
    expect(blocked.body.error).toBe('rate_limited')
    expect(Number(blocked.headers['retry-after'])).toBeGreaterThan(0)
  })

  it('allows requests when the limiter backend is down', async () => {
    app = buildApp({ broken: true })
    const token = await signToken('user-42')

    // Failing closed would turn a Redis blip into a full API outage.
    const res = await request(app).get('/me').set('Authorization', `Bearer ${token}`)
    expect(res.status).toBe(200)
  })

  it('does not rate limit the health check', async () => {
    app = buildApp({ limit: 1 })
    await request(app).get('/health')
    const second = await request(app).get('/health')
    expect(second.status).toBe(200)
  })

  it('returns 404 as JSON for an unknown route', async () => {
    const res = await request(app).get('/nope')
    expect(res.status).toBe(404)
    expect(res.body).toEqual({ error: 'not_found' })
  })

  it('omits the x-powered-by header', async () => {
    const res = await request(app).get('/health')
    expect(res.headers['x-powered-by']).toBeUndefined()
  })
})
