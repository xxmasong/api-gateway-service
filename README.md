# api-gateway-service

An API gateway in TypeScript: JWT authentication, refresh-token rotation with
reuse detection, and sliding-window rate limiting. **47 tests**, no Redis or
database required to run them.

The two pieces worth reading are the ones that are usually got wrong.

## Sliding-window rate limiting

A fixed window — "1000 requests per hour, reset on the hour" — lets a caller spend
its full quota in the last second of one window and again in the first second of
the next. That is twice the intended rate across the boundary, and it is the
default behaviour of most naive counters.

`src/lib/rateLimiter.ts` keeps a Redis sorted set of request timestamps per key
and trims anything older than the window, so the limit holds over *every*
interval rather than aligned ones. Two details that matter:

- **Members are unique per request** (`${now}-${random}`), not bare timestamps.
  Two requests in the same millisecond would otherwise collide in the set and the
  burst would be under-counted.
- **The limiter fails open.** If Redis is unreachable the request is allowed and a
  warning logged. Failing closed would turn a Redis blip into a total API outage,
  which is a worse failure than briefly unmetered traffic.

Keys prefer the authenticated user id over the IP: keying on IP alone lumps
everyone behind a NAT into one bucket and lets an authenticated caller evade the
limit by rotating addresses.

## Refresh-token rotation with reuse detection

`src/lib/tokens.ts` issues short-lived access tokens alongside a long-lived
refresh token, and rotates the refresh token on every use.

Tokens from one login share a **family id**. If a token is presented that has
already been rotated, that is a replay — either a buggy client or a stolen token —
and because there is no way to tell the thief from the victim, the entire family
is revoked and every session from that login ends. A different device's family is
untouched.

Refresh tokens are stored only as SHA-256 digests, so a leaked table yields
nothing usable.

```
login ──▶ [access, refresh₁]  family=f1
refresh₁ ─▶ [access, refresh₂]  family=f1, refresh₁ marked used
refresh₁ ─▶ REUSE DETECTED ──▶ revoke family f1 entirely
refresh₂ ─▶ rejected: revoked
```

## Running it

```bash
npm install
cp .env.example .env     # JWT_SECRET must be at least 32 characters
docker run -p 6379:6379 redis:7-alpine
npm run dev
```

The service refuses to boot on a missing or short `JWT_SECRET` rather than serving
traffic with a weak key, and drains in-flight requests on `SIGTERM` so a deploy
does not drop responses.

| Route | Auth | Notes |
| --- | --- | --- |
| `GET /health` | none | Registered before the limiter, so probes are never throttled |
| `POST /auth/login` | none | Stubbed 501; wire it to your user store. Separately rate limited by IP |
| `GET /me` | required | Returns the verified subject and claims |

Responses carry `RateLimit-Limit`, `RateLimit-Remaining` and `RateLimit-Reset`;
a 429 adds `Retry-After`.

## Tests

```bash
npm test          # 47 tests
npm run typecheck
```

Redis is faked in memory and the JWTs are real (signed with `jose`), so the suite
needs no services. `tests/app.test.ts` drives the middleware over actual HTTP with
supertest.

Notable cases: no double burst across a window boundary; same-millisecond requests
counted separately; reuse revoking a family while leaving others alive; the gateway
staying up when the limiter's backend throws; and identical 401 messages for
expired, malformed and wrongly-signed tokens, since the difference helps an
attacker and not a legitimate client.

## Design notes

`RedisLike` is declared structurally rather than importing ioredis's types, so the
limiter can be tested against a fake and swapped for another client. It also
normalises `exec()` results: ioredis returns `[error, result]` tuples per queued
command while other clients return bare values, and `unwrapPipeline` accepts both.

## Known limits

- `POST /auth/login` is a stub. Credential verification and the user store are out
  of scope; `TokenService` is the part that was worth building.
- No proxying or service discovery yet, so "gateway" describes the auth and
  limiting edge rather than a full reverse proxy.
- Access tokens are HS256 (shared secret). Multi-service deployments want RS256 or
  EdDSA with a published JWKS so verifiers need no secret.
- The rate limiter needs two round trips on the allow path. A Lua script would
  make it a single atomic call.

## Licence

MIT
