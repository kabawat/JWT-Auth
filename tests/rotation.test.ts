import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import assert from 'node:assert/strict';
import { verifyToken } from '../src/verify.js';
import { createToken } from '../src/create.js';
import { _resetKeys } from '../src/keys.js';
import { ERROR_CODES, StudioJwtError } from '../src/errors.js';
import type { SignConfig, VerifyConfig } from '../src/types.js';
import {
  generateTestRsaKeyPair,
  exportJwkFromPublicKeyPem,
  createTempKeyFile,
  startMockJwksServer,
  type KeyPairResult,
  type TempKeyFile,
  type MockJwksServer,
} from './test-utils.js';

describe('Key Rotation & Multi-Key JWKS', () => {
  let keypair1: KeyPairResult;
  let keypair2: KeyPairResult;
  let tempKey1: TempKeyFile;
  let tempKey2: TempKeyFile;
  let mockServer: MockJwksServer;

  const kid1 = 'auth-rs256-1';
  const kid2 = 'auth-rs256-2';

  let verifyConfig: VerifyConfig;
  let signConfigKey1: SignConfig;
  let signConfigKey2: SignConfig;

  beforeEach(async () => {
    keypair1 = generateTestRsaKeyPair();
    keypair2 = generateTestRsaKeyPair();

    tempKey1 = createTempKeyFile(keypair1.privateKey, 'key1.pem');
    tempKey2 = createTempKeyFile(keypair2.privateKey, 'key2.pem');

    const jwk1 = exportJwkFromPublicKeyPem(keypair1.publicKey, kid1);
    const jwk2 = exportJwkFromPublicKeyPem(keypair2.publicKey, kid2);

    mockServer = await startMockJwksServer({ keys: [jwk1, jwk2] });

    verifyConfig = {
      jwksUrl: mockServer.url,
      issuer: 'studio-auth',
      audience: 'studio-api',
      cooldownDuration: 0,
    };

    signConfigKey1 = {
      privateKeyPath: tempKey1.filePath,
      kid: kid1,
      issuer: 'studio-auth',
      audience: 'studio-api',
      expiresIn: '15m',
    };

    signConfigKey2 = {
      privateKeyPath: tempKey2.filePath,
      kid: kid2,
      issuer: 'studio-auth',
      audience: 'studio-api',
      expiresIn: '15m',
    };

    _resetKeys();
  });

  afterEach(async () => {
    if (mockServer) {
      await mockServer.close();
    }
    if (tempKey1) {
      tempKey1.cleanup();
    }
    if (tempKey2) {
      tempKey2.cleanup();
    }
    _resetKeys();
  });

  it('verifies tokens signed with multiple distinct active keys in JWKS', async () => {
    const token1 = await createToken({ sub: 'user-key1' }, signConfigKey1);
    const token2 = await createToken({ sub: 'user-key2' }, signConfigKey2);

    const payload1 = await verifyToken(token1, verifyConfig);
    const payload2 = await verifyToken(token2, verifyConfig);

    expect(payload1.sub).toBe('user-key1');
    expect(payload2.sub).toBe('user-key2');
  });

  it('demonstrates safe zero-downtime key rotation lifecycle', async () => {
    const jwk1 = exportJwkFromPublicKeyPem(keypair1.publicKey, kid1);
    mockServer.setJwks({ keys: [jwk1] });

    const tokenOldKey = await createToken({ sub: 'user-before-rotation' }, signConfigKey1);
    const payloadOld1 = await verifyToken(tokenOldKey, verifyConfig);
    expect(payloadOld1.sub).toBe('user-before-rotation');

    const jwk2 = exportJwkFromPublicKeyPem(keypair2.publicKey, kid2);
    mockServer.setJwks({ keys: [jwk1, jwk2] });

    const tokenNewKey = await createToken({ sub: 'user-after-rotation' }, signConfigKey2);

    const payloadNew = await verifyToken(tokenNewKey, verifyConfig);
    const payloadOld2 = await verifyToken(tokenOldKey, verifyConfig);
    expect(payloadNew.sub).toBe('user-after-rotation');
    expect(payloadOld2.sub).toBe('user-before-rotation');

    mockServer.setJwks({ keys: [jwk2] });
    _resetKeys();

    const payloadNewAfterRetirement = await verifyToken(tokenNewKey, verifyConfig);
    expect(payloadNewAfterRetirement.sub).toBe('user-after-rotation');

    await assert.rejects(
      async () => verifyToken(tokenOldKey, verifyConfig),
      (err) => {
        assert.ok(err instanceof StudioJwtError);
        assert.equal(err.code, ERROR_CODES.UNKNOWN_KID);
        return true;
      },
    );
  });

  it('caches JWKS in memory and avoids network calls on subsequent verifications', async () => {
    const token = await createToken({ sub: 'cached-user' }, signConfigKey1);
    const initialCount = mockServer.getRequestCount();

    await verifyToken(token, verifyConfig);
    expect(mockServer.getRequestCount()).toBe(initialCount + 1);

    for (let i = 0; i < 10; i++) {
      await verifyToken(token, verifyConfig);
    }
    expect(mockServer.getRequestCount()).toBe(initialCount + 1);
  });

  it('handles high concurrent verifications without errors or race conditions', async () => {
    const tokens = await Promise.all([
      createToken({ sub: 'concurrent-1' }, signConfigKey1),
      createToken({ sub: 'concurrent-2' }, signConfigKey2),
      createToken({ sub: 'concurrent-3' }, signConfigKey1),
    ]);

    const promises = Array.from({ length: 60 }, (_, i) =>
      verifyToken(tokens[i % tokens.length]!, verifyConfig),
    );

    const results = await Promise.all(promises);
    expect(results.length).toBe(60);
    for (let i = 0; i < 60; i++) {
      expect(results[i]!.sub.startsWith('concurrent-')).toBe(true);
      expect(results[i]!.type).toBe('access');
    }
  });
});
