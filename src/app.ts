import express, { type Express, type NextFunction, type Request, type Response } from 'express'

import type { RateLimiter } from './lib/rateLimiter.js'
import { optionalAuth, requireAuth, type AuthOptions } from './middleware/auth.js'
import { rateLimit } from './middleware/rateLimit.js'

export interface AppDependencies {
  auth: AuthOptions
  /** Applied to every request. */
  globalLimiter: RateLimiter
  /** Applied to the auth routes, keyed by IP, to blunt credential stuffing. */
  loginLimiter: RateLimiter
}

export function createApp(deps: AppDependencies): Express {
  const app = express()

  app.use(express.json({ limit: '1mb' }))
  app.disable('x-powered-by')

  app.get('/health', (_req, res) => {
    res.json({ status: 'ok' })
  })

  // Anonymous callers are limited by IP, authenticated ones by user id, so
  // optionalAuth has to resolve the identity before the limiter reads it.
  app.use(optionalAuth(deps.auth))
  app.use(rateLimit(deps.globalLimiter))

  app.post(
    '/auth/login',
    rateLimit(deps.loginLimiter, { keyFor: (req) => `login:${req.ip ?? 'unknown'}` }),
    (_req, res) => {
      res.status(501).json({ error: 'not_implemented', message: 'Wire this to your user store.' })
    },
  )

  app.get('/me', requireAuth(deps.auth), (req, res) => {
    res.json({ userId: req.userId, claims: req.claims })
  })

  app.use((_req, res) => {
    res.status(404).json({ error: 'not_found' })
  })

  app.use((error: Error, req: Request, res: Response, _next: NextFunction) => {
    req.log?.warn({ err: error }, 'unhandled error')
    // Never leak an internal message or stack to the client.
    res.status(500).json({ error: 'internal_error' })
  })

  return app
}
