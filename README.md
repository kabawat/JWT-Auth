# @kabawat/jwt-auth

Production-ready, lightweight RS256 JWT creation and JWKS verification engine for distributed services.

---

## Installation

```bash
npm install @kabawat/jwt-auth
```

Published publicly to the official [npm registry](https://www.npmjs.com/package/@kabawat/jwt-auth).

---

## How to Use

The package exposes modular entry points:
- `@kabawat/jwt-auth` — Unified entry point (exports `createToken`, `verifyToken`, error classes, and TypeScript types)
- `@kabawat/jwt-auth/create` — Issue RS256 tokens (Auth Service)
- `@kabawat/jwt-auth/verify` — Verify RS256 tokens via JWKS with key rotation & in-memory caching (Downstream Services)
- `@kabawat/jwt-auth/errors` — Structured operational errors & codes
- `@kabawat/jwt-auth/config` — Configuration validation schemas

---

### 1. Create Token (Auth Service)

```typescript
import { createToken } from '@kabawat/jwt-auth/create';

const token = await createToken(
  {
    sub: 'user_123',
    role: 'ADMIN',
    actor: 'COMPANY_STAFF',
    sid: 'session_abc', // custom claims
  },
  {
    privateKeyPath: 'keys/access-private.pem', // or privateKey: 'PEM_STRING'
    kid: 'auth-rs256-1',
    issuer: 'salon-x-auth',
    audience: 'salon-x',
    expiresIn: '15m', // e.g. '15m', '1h', '300s'
  }
);
```

---

### 2. Verify Token (Downstream Microservices)

```typescript
import { verifyToken } from '@kabawat/jwt-auth/verify';

try {
  const payload = await verifyToken(token, {
    jwksUrl: 'https://auth.salon-x.internal/.well-known/jwks.json',
    issuer: 'salon-x-auth',
    audience: 'salon-x',
    clockTolerance: 5, // optional seconds
  });

  console.log(`Authenticated user: ${payload.sub}, role: ${payload.role}`);
} catch (err) {
  if (err.code === 'TOKEN_EXPIRED') {
    // Return 401 token expired
  } else if (err.code === 'JWKS_UNAVAILABLE') {
    // Return 503 auth service temporarily unavailable
  }
}
```

---

### 3. Key Rotation Lifecycle

Supports zero-downtime key rotation:
1. Generate new keypair with a new `kid` (e.g. `auth-rs256-2`).
2. Publish both keys (old + new) in Auth Service JWKS.
3. Switch Auth Service signer to use `auth-rs256-2`.
4. After existing tokens expire, retire the old key from JWKS.

---

## Scripts

```bash
# Typecheck TypeScript definitions
npm run typecheck

# Build and generate dist/
npm run build

# Run unit tests
npm test

# Run end-to-end manual test example
npm run manual-test

# Full pre-publish verification
npm run verify
```

---

## License

MIT © [Kabawat](https://github.com/kabawat)
