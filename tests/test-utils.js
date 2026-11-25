import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import crypto from 'node:crypto';

export function generateTestRsaKeyPair() {
  const { privateKey, publicKey } = crypto.generateKeyPairSync('rsa', {
    modulusLength: 2048,
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
  });

  return { privateKey, publicKey };
}

export function generatePkcs1KeyPair() {
  const { privateKey, publicKey } = crypto.generateKeyPairSync('rsa', {
    modulusLength: 2048,
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs1', format: 'pem' },
  });

  return { privateKey, publicKey };
}

export function exportJwkFromPublicKeyPem(publicKeyPem, kid) {
  const keyObj = crypto.createPublicKey(publicKeyPem);
  const jwk = keyObj.export({ format: 'jwk' });
  return {
    kty: jwk.kty,
    n: jwk.n,
    e: jwk.e,
    use: 'sig',
    kid,
    alg: 'RS256',
  };
}

export function createTempKeyFile(content, filename = 'test-private.pem') {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'jwt-test-'));
  const filePath = path.join(tmpDir, filename);
  fs.writeFileSync(filePath, content, { mode: 0o600 });
  return {
    filePath,
    cleanup() {
      try {
        fs.rmSync(tmpDir, { recursive: true, force: true });
      } catch {
        // ignore
      }
    },
  };
}

export function startMockJwksServer(initialJwks) {
  let jwksData = initialJwks;
  let requestCount = 0;
  let delayMs = 0;
  let statusCode = 200;

  const server = http.createServer((req, res) => {
    requestCount += 1;

    const respond = () => {
      if (statusCode !== 200) {
        res.writeHead(statusCode, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'server error' }));
        return;
      }

      res.writeHead(200, {
        'Content-Type': 'application/json',
        'Cache-Control': 'public, max-age=600',
      });
      res.end(JSON.stringify(jwksData));
    };

    if (delayMs > 0) {
      setTimeout(respond, delayMs);
    } else {
      respond();
    }
  });

  return new Promise((resolve) => {
    server.listen(0, '127.0.0.1', () => {
      const port = server.address().port;
      const url = `http://127.0.0.1:${port}/.well-known/jwks.json`;

      resolve({
        server,
        url,
        port,
        getRequestCount: () => requestCount,
        setJwks: (newJwks) => {
          jwksData = newJwks;
        },
        setDelay: (ms) => {
          delayMs = ms;
        },
        setStatusCode: (code) => {
          statusCode = code;
        },
        close: () => new Promise((done) => server.close(done)),
      });
    });
  });
}
