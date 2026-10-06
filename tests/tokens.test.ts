import { beforeEach, describe, expect, it } from 'vitest'

import {
  InvalidTokenError,
  TokenReuseError,
  TokenService,
  constantTimeEquals,
  hashToken,
  type RefreshRecord,
  type RefreshStore,
} from '../src/lib/tokens'

class MemoryStore implements RefreshStore {
  records = new Map<string, RefreshRecord>()

  async save(record: RefreshRecord): Promise<void> {
    this.records.set(record.tokenHash, { ...record })
  }

  async findByHash(tokenHash: string): Promise<RefreshRecord | null> {
    const found = this.records.get(tokenHash)
    return found ? { ...found } : null
  }

  async markUsed(tokenHash: string, usedAt: number): Promise<void> {
    const record = this.records.get(tokenHash)
    if (record) record.usedAt = usedAt
  }

  async revokeFamily(familyId: string, revokedAt: number): Promise<number> {
    let count = 0
    for (const record of this.records.values()) {
      if (record.familyId === familyId && record.revokedAt === null) {
        record.revokedAt = revokedAt
        count += 1
      }
    }
    return count
  }

  familyOf(tokenHash: string): string | undefined {
    return this.records.get(tokenHash)?.familyId
  }
}

function makeService(store: RefreshStore) {
  return new TokenService(store, {
    accessTtlMs: 15 * 60 * 1000,
    refreshTtlMs: 30 * 24 * 60 * 60 * 1000,
    // A real deployment signs with jose; the shape is all these tests need.
    signAccessToken: (claims) => `access.${claims.sub}.${claims.exp}`,
  })
}

describe('hashToken', () => {
  it('is stable and does not echo the input', () => {
    const hash = hashToken('secret-token')
    expect(hash).toBe(hashToken('secret-token'))
    expect(hash).not.toContain('secret-token')
    expect(hash).toHaveLength(64)
  })

  it('differs for different inputs', () => {
    expect(hashToken('a')).not.toBe(hashToken('b'))
  })
})

describe('constantTimeEquals', () => {
  it('matches identical strings', () => {
    expect(constantTimeEquals('abc123', 'abc123')).toBe(true)
  })

  it('rejects different strings of equal length', () => {
    expect(constantTimeEquals('abc123', 'abc124')).toBe(false)
  })

  it('rejects a length mismatch without throwing', () => {
    expect(constantTimeEquals('short', 'much-longer-value')).toBe(false)
  })
})

describe('TokenService', () => {
  let store: MemoryStore
  let service: TokenService

  beforeEach(() => {
    store = new MemoryStore()
    service = makeService(store)
  })

  it('issues a pair on login', async () => {
    const now = 1_700_000_000_000
    const pair = await service.login('user-1', now)

    expect(pair.accessToken).toBe(`access.user-1.${Math.floor((now + 900_000) / 1000)}`)
    expect(pair.refreshToken).toBeTruthy()
    expect(pair.refreshExpiresAt).toBeGreaterThan(pair.accessExpiresAt)
  })

  it('stores only the hash of the refresh token', async () => {
    const pair = await service.login('user-1')
    expect(store.records.has(hashToken(pair.refreshToken))).toBe(true)
    // A leaked table must not yield usable tokens.
    for (const key of store.records.keys()) {
      expect(key).not.toBe(pair.refreshToken)
    }
  })

  it('rotates the token on refresh', async () => {
    const first = await service.login('user-1', 1000)
    const second = await service.refresh(first.refreshToken, 2000)

    expect(second.refreshToken).not.toBe(first.refreshToken)
    expect(second.accessToken).not.toBe(first.accessToken)
  })

  it('keeps the rotated token in the same family', async () => {
    const first = await service.login('user-1', 1000)
    const second = await service.refresh(first.refreshToken, 2000)

    expect(store.familyOf(hashToken(second.refreshToken))).toBe(
      store.familyOf(hashToken(first.refreshToken)),
    )
  })

  it('starts a separate family per login', async () => {
    const a = await service.login('user-1', 1000)
    const b = await service.login('user-1', 2000)

    expect(store.familyOf(hashToken(a.refreshToken))).not.toBe(
      store.familyOf(hashToken(b.refreshToken)),
    )
  })

  it('rejects an unknown token', async () => {
    await expect(service.refresh('not-a-real-token')).rejects.toThrow(InvalidTokenError)
  })

  it('rejects an expired token', async () => {
    const pair = await service.login('user-1', 1000)
    const afterExpiry = 1000 + 30 * 24 * 60 * 60 * 1000 + 1
    await expect(service.refresh(pair.refreshToken, afterExpiry)).rejects.toThrow(InvalidTokenError)
  })

  it('detects reuse of an already-rotated token', async () => {
    const first = await service.login('user-1', 1000)
    await service.refresh(first.refreshToken, 2000)

    await expect(service.refresh(first.refreshToken, 3000)).rejects.toThrow(TokenReuseError)
  })

  it('revokes the whole family when reuse is detected', async () => {
    const first = await service.login('user-1', 1000)
    const second = await service.refresh(first.refreshToken, 2000)

    // Replay the old token: the attacker's and the victim's sessions both end,
    // because there is no way to tell which holder is legitimate.
    await expect(service.refresh(first.refreshToken, 3000)).rejects.toThrow(TokenReuseError)
    await expect(service.refresh(second.refreshToken, 4000)).rejects.toThrow(InvalidTokenError)
  })

  it('leaves other families untouched by a revocation', async () => {
    const compromised = await service.login('user-1', 1000)
    const other = await service.login('user-1', 1100)

    await service.refresh(compromised.refreshToken, 2000)
    await expect(service.refresh(compromised.refreshToken, 3000)).rejects.toThrow(TokenReuseError)

    // A different device's session must survive.
    await expect(service.refresh(other.refreshToken, 4000)).resolves.toBeTruthy()
  })

  it('reports the family on the reuse error', async () => {
    const pair = await service.login('user-1', 1000)
    const familyId = store.familyOf(hashToken(pair.refreshToken))
    await service.refresh(pair.refreshToken, 2000)

    await expect(service.refresh(pair.refreshToken, 3000)).rejects.toMatchObject({ familyId })
  })

  it('supports a chain of rotations', async () => {
    let pair = await service.login('user-1', 1000)
    for (let i = 1; i <= 5; i += 1) {
      pair = await service.refresh(pair.refreshToken, 1000 + i * 1000)
    }
    expect(pair.refreshToken).toBeTruthy()
  })

  it('revokes the family on logout', async () => {
    const pair = await service.login('user-1', 1000)
    const revoked = await service.logout(pair.refreshToken, 2000)

    expect(revoked).toBe(1)
    await expect(service.refresh(pair.refreshToken, 3000)).rejects.toThrow(InvalidTokenError)
  })

  it('ends every session in the family on logout', async () => {
    const first = await service.login('user-1', 1000)
    const second = await service.refresh(first.refreshToken, 2000)

    await service.logout(second.refreshToken, 3000)
    await expect(service.refresh(second.refreshToken, 4000)).rejects.toThrow(InvalidTokenError)
  })

  it('treats logout of an unknown token as a no-op', async () => {
    expect(await service.logout('unknown')).toBe(0)
  })
})
