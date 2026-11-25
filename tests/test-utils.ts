import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import crypto from 'node:crypto';

export interface KeyPairResult {
  privateKey: string;
  publicKey: string;
}

export interface JwkResult {
  kty: string;
  n: string;
  e: string;
  use: string;
  kid: string;
  alg: string;
}

export interface TempKeyFile {
  filePath: string;
  cleanup: () => void;
}

export interface MockJwksServer {
  server: http.Server;
  url: string;
  port: number;
  getRequestCount: () => number;
  setJwks: (newJwks: Record<string, unknown>) => void;
  setDelay: (ms: number) => void;
  setStatusCode: (code: number) => void;
  close: () => Promise<void>;
}

export function generateTestRsaKeyPair(): KeyPairResult {
  const { privateKey, publicKey } = crypto.generateKeyPairSync('rsa', {
    modulusLength: 2048,
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
  });

  return { privateKey, publicKey };
}

export function generatePkcs1KeyPair(): KeyPairResult {
  const { privateKey, publicKey } = crypto.generateKeyPairSync('rsa', {
    modulusLength: 2048,
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs1', format: 'pem' },
  });

  return { privateKey, publicKey };
}

export function exportJwkFromPublicKeyPem(publicKeyPem: string, kid: string): JwkResult {
  const keyObj = crypto.createPublicKey(publicKeyPem);
  const jwk = keyObj.export({ format: 'jwk' });
  return {
    kty: jwk.kty!,
    n: jwk.n!,
    e: jwk.e!,
    use: 'sig',
    kid,
    alg: 'RS256',
  };
}

export function createTempKeyFile(content: string, filename = 'test-private.pem'): TempKeyFile {
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

export function startMockJwksServer(initialJwks: Record<string, unknown>): Promise<MockJwksServer> {
  let jwksData = initialJwks;
  let requestCount = 0;
  let delayMs = 0;
  let statusCode = 200;

  const server = http.createServer((_req, res) => {
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
      const addr = server.address() as { port: number };
      const port = addr.port;
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
        close: () => new Promise<void>((done) => {
          server.close(() => done());
        }),
      });
    });
  });
}
