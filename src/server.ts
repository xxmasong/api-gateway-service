import Redis from 'ioredis'
import pino from 'pino'

import { createApp } from './app.js'
import { RateLimiter } from './lib/rateLimiter.js'

const logger = pino({ level: process.env.LOG_LEVEL ?? 'info' })

const JWT_SECRET = process.env.JWT_SECRET
if (!JWT_SECRET || JWT_SECRET.length < 32) {
  // Fail at boot rather than serving traffic with a weak or missing key.
  logger.error('JWT_SECRET must be set and at least 32 characters')
  process.exit(1)
}

const redis = new Redis(process.env.REDIS_URL ?? 'redis://localhost:6379')
redis.on('error', (err) => logger.warn({ err }, 'redis error'))

const app = createApp({
  auth: {
    secret: new TextEncoder().encode(JWT_SECRET),
    issuer: process.env.JWT_ISSUER,
    audience: process.env.JWT_AUDIENCE,
  },
  globalLimiter: new RateLimiter(redis, {
    limit: Number(process.env.RATE_LIMIT ?? 1000),
    windowMs: Number(process.env.RATE_WINDOW_MS ?? 60_000),
    prefix: 'global',
  }),
  loginLimiter: new RateLimiter(redis, {
    limit: Number(process.env.LOGIN_RATE_LIMIT ?? 5),
    windowMs: Number(process.env.LOGIN_RATE_WINDOW_MS ?? 300_000),
    prefix: 'login',
  }),
})

const port = Number(process.env.PORT ?? 3000)
const server = app.listen(port, () => logger.info({ port }, 'gateway listening'))

// Drain in-flight requests before exiting so a deploy does not drop responses.
for (const signal of ['SIGTERM', 'SIGINT'] as const) {
  process.on(signal, () => {
    logger.info({ signal }, 'shutting down')
    server.close(() => {
      redis.quit().finally(() => process.exit(0))
    })
  })
}
