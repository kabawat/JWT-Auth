import { describe, it, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import { verifyToken } from '../src/verify.js';
import { createToken } from '../src/create.js';
import { _resetKeys } from '../src/keys.js';
import { ERROR_CODES, StudioJwtError } from '../src/errors.js';
import {
  generateTestRsaKeyPair,
  exportJwkFromPublicKeyPem,
  createTempKeyFile,
  startMockJwksServer,
} from './test-utils.js';

describe('Key Rotation & Multi-Key JWKS', () => {
  let keypair1;
  let keypair2;
  let tempKey1;
  let tempKey2;
  let mockServer;

  const kid1 = 'auth-rs256-1';
  const kid2 = 'auth-rs256-2';

  let verifyConfig;
  let signConfigKey1;
  let signConfigKey2;

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

    assert.equal(payload1.sub, 'user-key1');
    assert.equal(payload2.sub, 'user-key2');
  });

  it('demonstrates safe zero-downtime key rotation lifecycle', async () => {
    // Step 1: Start with only key 1 in JWKS
    const jwk1 = exportJwkFromPublicKeyPem(keypair1.publicKey, kid1);
    mockServer.setJwks({ keys: [jwk1] });

    const tokenOldKey = await createToken({ sub: 'user-before-rotation' }, signConfigKey1);
    const payloadOld1 = await verifyToken(tokenOldKey, verifyConfig);
    assert.equal(payloadOld1.sub, 'user-before-rotation');

    // Step 2: Key Introduction - JWKS updated with both key 1 and key 2 (overlapping)
    const jwk2 = exportJwkFromPublicKeyPem(keypair2.publicKey, kid2);
    mockServer.setJwks({ keys: [jwk1, jwk2] });

    // Step 3: Signer Switch - Auth switches to key 2
    const tokenNewKey = await createToken({ sub: 'user-after-rotation' }, signConfigKey2);

    // Step 4: Overlapping verification - both old and new tokens verify
    const payloadNew = await verifyToken(tokenNewKey, verifyConfig);
    const payloadOld2 = await verifyToken(tokenOldKey, verifyConfig);
    assert.equal(payloadNew.sub, 'user-after-rotation');
    assert.equal(payloadOld2.sub, 'user-before-rotation');

    // Step 5: Key Retirement - Remove key 1 from JWKS
    mockServer.setJwks({ keys: [jwk2] });
    _resetKeys(); // Simulate cache eviction

    // New token continues to verify
    const payloadNewAfterRetirement = await verifyToken(tokenNewKey, verifyConfig);
    assert.equal(payloadNewAfterRetirement.sub, 'user-after-rotation');

    // Old token with retired key is rejected
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

    // First verification hits JWKS
    await verifyToken(token, verifyConfig);
    assert.equal(mockServer.getRequestCount(), initialCount + 1);

    // Subsequent 10 verifications use cached key (zero extra requests)
    for (let i = 0; i < 10; i++) {
      await verifyToken(token, verifyConfig);
    }
    assert.equal(mockServer.getRequestCount(), initialCount + 1);
  });

  it('handles high concurrent verifications without errors or race conditions', async () => {
    const tokens = await Promise.all([
      createToken({ sub: 'concurrent-1' }, signConfigKey1),
      createToken({ sub: 'concurrent-2' }, signConfigKey2),
      createToken({ sub: 'concurrent-3' }, signConfigKey1),
    ]);

    const promises = Array.from({ length: 60 }, (_, i) =>
      verifyToken(tokens[i % tokens.length], verifyConfig),
    );

    const results = await Promise.all(promises);
    assert.equal(results.length, 60);
    for (let i = 0; i < 60; i++) {
      assert.ok(results[i].sub.startsWith('concurrent-'));
      assert.equal(results[i].type, 'access');
    }
  });
});
