/**
 * Access and refresh token issuing, with rotation and reuse detection.
 *
 * Refresh tokens are rotated on every use: redeeming one invalidates it and
 * returns a fresh pair. Tokens are grouped into a "family" per login, so if a
 * stolen token is replayed after the legitimate client has already rotated it,
 * the reuse is detectable — and the response is to revoke the whole family,
 * because at that point there is no way to tell thief from victim.
 */

import { createHash, randomBytes, timingSafeEqual } from 'node:crypto'

export interface TokenPair {
  accessToken: string
  refreshToken: string
  accessExpiresAt: number
  refreshExpiresAt: number
}

export interface RefreshRecord {
  tokenHash: string
  userId: string
  familyId: string
  expiresAt: number
  usedAt: number | null
  revokedAt: number | null
}

export interface RefreshStore {
  save(record: RefreshRecord): Promise<void>
  findByHash(tokenHash: string): Promise<RefreshRecord | null>
  markUsed(tokenHash: string, usedAt: number): Promise<void>
  revokeFamily(familyId: string, revokedAt: number): Promise<number>
}

export class TokenReuseError extends Error {
  constructor(readonly familyId: string) {
    super('refresh token was already used; the token family has been revoked')
    this.name = 'TokenReuseError'
  }
}

export class InvalidTokenError extends Error {
  constructor(message = 'refresh token is invalid or expired') {
    super(message)
    this.name = 'InvalidTokenError'
  }
}

/** Refresh tokens are stored as SHA-256 digests: a leaked table yields no usable tokens. */
export function hashToken(token: string): string {
  return createHash('sha256').update(token).digest('hex')
}

export function constantTimeEquals(a: string, b: string): boolean {
  const left = Buffer.from(a)
  const right = Buffer.from(b)
  // timingSafeEqual throws on a length mismatch, which would itself leak length.
  if (left.length !== right.length) return false
  return timingSafeEqual(left, right)
}

export interface TokenServiceOptions {
  accessTtlMs?: number
  refreshTtlMs?: number
  signAccessToken: (claims: { sub: string; exp: number }) => string
}

export class TokenService {
  private readonly accessTtlMs: number
  private readonly refreshTtlMs: number
  private readonly signAccessToken: TokenServiceOptions['signAccessToken']

  constructor(
    private readonly store: RefreshStore,
    options: TokenServiceOptions,
  ) {
    this.accessTtlMs = options.accessTtlMs ?? 15 * 60 * 1000
    this.refreshTtlMs = options.refreshTtlMs ?? 30 * 24 * 60 * 60 * 1000
    this.signAccessToken = options.signAccessToken
  }

  private async issue(userId: string, familyId: string, now: number): Promise<TokenPair> {
    const refreshToken = randomBytes(32).toString('base64url')
    const refreshExpiresAt = now + this.refreshTtlMs
    const accessExpiresAt = now + this.accessTtlMs

    await this.store.save({
      tokenHash: hashToken(refreshToken),
      userId,
      familyId,
      expiresAt: refreshExpiresAt,
      usedAt: null,
      revokedAt: null,
    })

    return {
      accessToken: this.signAccessToken({
        sub: userId,
        exp: Math.floor(accessExpiresAt / 1000),
      }),
      refreshToken,
      accessExpiresAt,
      refreshExpiresAt,
    }
  }

  /** Begin a new session, starting a fresh token family. */
  async login(userId: string, now = Date.now()): Promise<TokenPair> {
    return this.issue(userId, randomBytes(16).toString('hex'), now)
  }

  /** Redeem a refresh token for a new pair, invalidating the one presented. */
  async refresh(refreshToken: string, now = Date.now()): Promise<TokenPair> {
    const record = await this.store.findByHash(hashToken(refreshToken))

    if (!record) throw new InvalidTokenError()
    if (record.revokedAt !== null) throw new InvalidTokenError('refresh token was revoked')
    if (record.expiresAt <= now) throw new InvalidTokenError()

    if (record.usedAt !== null) {
      // Replay of an already-rotated token. Either the client is buggy or a token
      // leaked; both warrant ending every session in the family.
      await this.store.revokeFamily(record.familyId, now)
      throw new TokenReuseError(record.familyId)
    }

    await this.store.markUsed(record.tokenHash, now)
    return this.issue(record.userId, record.familyId, now)
  }

  /** End every session in the family the token belongs to. */
  async logout(refreshToken: string, now = Date.now()): Promise<number> {
    const record = await this.store.findByHash(hashToken(refreshToken))
    if (!record) return 0
    return this.store.revokeFamily(record.familyId, now)
  }
}
