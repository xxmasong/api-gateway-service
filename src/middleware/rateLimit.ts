import type { NextFunction, Request, Response } from 'express'

import type { RateLimiter } from '../lib/rateLimiter.js'

export interface RateLimitMiddlewareOptions {
  /** Derives the bucket key. Defaults to the authenticated user, else the IP. */
  keyFor?: (req: Request) => string
}

function defaultKey(req: Request): string {
  const userId = (req as Request & { userId?: string }).userId
  // Prefer the user id: keying only on IP lumps everyone behind one NAT together,
  // and lets an authenticated caller dodge the limit by rotating addresses.
  if (userId) return `user:${userId}`
  return `ip:${req.ip ?? 'unknown'}`
}

export function rateLimit(limiter: RateLimiter, options: RateLimitMiddlewareOptions = {}) {
  const keyFor = options.keyFor ?? defaultKey

  return async function rateLimitMiddleware(req: Request, res: Response, next: NextFunction) {
    try {
      const result = await limiter.check(keyFor(req))

      res.setHeader('RateLimit-Limit', String(result.limit))
      res.setHeader('RateLimit-Remaining', String(result.remaining))
      res.setHeader('RateLimit-Reset', String(Math.ceil((result.resetAt - Date.now()) / 1000)))

      if (!result.allowed) {
        res.setHeader('Retry-After', String(result.retryAfter))
        res.status(429).json({
          error: 'rate_limited',
          message: 'Too many requests. Retry after the interval in the Retry-After header.',
          retryAfter: result.retryAfter,
        })
        return
      }

      next()
    } catch (error) {
      // A limiter outage must not take the API down with it: log and allow.
      // Failing closed here would turn a Redis blip into a full outage.
      req.log?.warn({ err: error }, 'rate limiter unavailable; allowing the request')
      next()
    }
  }
}
