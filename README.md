# @studio/jwt

Lightweight RS256 JWT creation and JWKS verification for Studio microservices.

---

## Installation

```bash
npm install @studio/jwt
```

> **Note:** For GitHub Packages, ensure `.npmrc` includes:
> ```ini
> @studio:registry=https://npm.pkg.github.com
> //npm.pkg.github.com/:_authToken=${GITHUB_TOKEN}
> ```

---

## How to Use

The package exposes two isolated entry points:
- `@studio/jwt/create` — Issue tokens (Auth Service)
- `@studio/jwt/verify` — Verify tokens via JWKS (Downstream Services)

---

### 1. Create Token (Auth Service)

```javascript
import { createToken } from '@studio/jwt/create';

const token = await createToken(
  {
    sub: 'user_123',
    role: 'ADMIN',
    actor: 'COMPANY_STAFF',
    sid: 'session_abc', // optional custom claims
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

#### Create Config Options

| Option | Type | Description |
| :--- | :--- | :--- |
| `privateKeyPath` / `privateKey` | `string` | RSA private key file path or PEM string *(required)* |
| `kid` | `string` | Key ID matching the public JWKS key *(required)* |
| `issuer` | `string` | Expected issuer (`iss`) *(required)* |
| `audience` | `string` | Expected audience (`aud`) *(required)* |
| `expiresIn` | `string \| number` | Expiry duration (e.g., `'15m'`, `'1h'`) *(required)* |

---

### 2. Verify Token (Downstream Services / Middleware)

```javascript
import { verifyToken } from '@studio/jwt/verify';

const verifyConfig = {
  jwksUrl: 'http://studio.local/auth/.well-known/jwks.json',
  issuer: 'salon-x-auth',
  audience: 'salon-x',
};

// Express Middleware Example
export async function requireAuth(req, res, next) {
  const token = req.headers.authorization?.replace(/^Bearer\s+/, '');
  if (!token) {
    return res.status(401).json({ message: 'Missing token' });
  }

  try {
    const payload = await verifyToken(token, verifyConfig);
    req.auth = payload;
    next();
  } catch (err) {
    if (err.category === 'INFRASTRUCTURE') {
      return res.status(503).json({ message: 'Auth service unavailable' });
    }
    return res.status(401).json({ message: 'Invalid or expired token' });
  }
}
```

#### Verify Config Options

| Option | Type | Default | Description |
| :--- | :--- | :--- | :--- |
| `jwksUrl` | `string` | *required* | Auth service JWKS endpoint URL |
| `issuer` | `string` | *required* | Expected token issuer (`iss`) |
| `audience` | `string` | *required* | Expected token audience (`aud`) |
| `clockTolerance` | `number` | `5` | Clock skew tolerance in seconds |
| `cooldownDuration` | `number` | `30000` | Cooldown in ms between JWKS re-fetches |

---

## Error Handling

Errors thrown have a `code` and `category`:

- **`err.category === 'CREDENTIALS'`** (HTTP 401): Expired token (`TOKEN_EXPIRED`), invalid signature (`INVALID_SIGNATURE`), malformed token (`INVALID_TOKEN`), unknown kid (`UNKNOWN_KID`).
- **`err.category === 'INFRASTRUCTURE'`** (HTTP 500 / 503): Missing config (`CONFIG_ERROR`), JWKS unreachable (`JWKS_UNAVAILABLE`), private key read failure (`PRIVATE_KEY_LOAD_ERROR`).
