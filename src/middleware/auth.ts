import type { NextFunction, Request, Response } from 'express'
import { jwtVerify, type JWTPayload } from 'jose'

export interface AuthOptions {
  secret: Uint8Array
  issuer?: string
  audience?: string
}

declare module 'express-serve-static-core' {
  interface Request {
    userId?: string
    claims?: JWTPayload
    log?: { warn: (obj: unknown, msg?: string) => void }
  }
}

function bearerFrom(header: string | undefined): string | null {
  if (!header) return null
  const [scheme, token] = header.split(' ')
  // The scheme is case-insensitive per RFC 6750.
  if (!token || scheme?.toLowerCase() !== 'bearer') return null
  return token.trim() || null
}

/** Reject any request without a valid access token. */
export function requireAuth(options: AuthOptions) {
  return async function requireAuthMiddleware(req: Request, res: Response, next: NextFunction) {
    const token = bearerFrom(req.headers.authorization)

    if (!token) {
      res.status(401).json({ error: 'unauthorized', message: 'A bearer token is required.' })
      return
    }

    try {
      const { payload } = await jwtVerify(token, options.secret, {
        issuer: options.issuer,
        audience: options.audience,
      })

      if (!payload.sub) {
        res.status(401).json({ error: 'unauthorized', message: 'The token has no subject.' })
        return
      }

      req.userId = payload.sub
      req.claims = payload
      next()
    } catch {
      // Do not distinguish expired from malformed from wrong-signature: the
      // difference is useful to an attacker and not to a legitimate client.
      res.status(401).json({ error: 'unauthorized', message: 'The token is invalid or expired.' })
    }
  }
}

/** Attach claims when a valid token is present, but allow anonymous access. */
export function optionalAuth(options: AuthOptions) {
  return async function optionalAuthMiddleware(req: Request, _res: Response, next: NextFunction) {
    const token = bearerFrom(req.headers.authorization)
    if (!token) return next()

    try {
      const { payload } = await jwtVerify(token, options.secret, {
        issuer: options.issuer,
        audience: options.audience,
      })
      if (payload.sub) {
        req.userId = payload.sub
        req.claims = payload
      }
    } catch {
      // Ignore a bad token here; the route decides whether anonymous is allowed.
    }
    next()
  }
}
