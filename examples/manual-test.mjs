import crypto from 'node:crypto';
import http from 'node:http';
import { createToken, verifyToken } from '../dist/index.js';

// 1. Generate ephemeral RSA keypair
const { privateKey, publicKey } = crypto.generateKeyPairSync('rsa', {
  modulusLength: 2048,
  publicKeyEncoding: { type: 'spki', format: 'pem' },
  privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
});

const kid = 'example-key-1';
const keyObj = crypto.createPublicKey(publicKey);
const jwk = keyObj.export({ format: 'jwk' });
const jwksData = {
  keys: [{
    kty: jwk.kty,
    n: jwk.n,
    e: jwk.e,
    use: 'sig',
    kid,
    alg: 'RS256',
  }],
};

// 2. Start mock JWKS server
const server = http.createServer((req, res) => {
  res.writeHead(200, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify(jwksData));
});

server.listen(0, '127.0.0.1', async () => {
  const port = server.address().port;
  const jwksUrl = `http://127.0.0.1:${port}/.well-known/jwks.json`;

  try {
    // 3. Issue Token
    const token = await createToken(
      { sub: 'user_456', role: 'ADMIN', actor: 'COMPANY_STAFF' },
      {
        privateKey,
        kid,
        issuer: 'salon-auth',
        audience: 'salon-api',
        expiresIn: '15m',
      }
    );
    console.log('Token created successfully:\n', token.slice(0, 50) + '...\n');

    // 4. Verify Token
    const payload = await verifyToken(token, {
      jwksUrl,
      issuer: 'salon-auth',
      audience: 'salon-api',
    });
    console.log('Token verified payload:\n', payload);
  } finally {
    server.close();
  }
});
