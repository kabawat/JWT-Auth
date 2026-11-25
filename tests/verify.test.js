import { describe, it, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import { SignJWT, importPKCS8 } from 'jose';
import { verifyToken } from '../dist/verify.js';
import { createToken } from '../dist/create.js';
import { _resetKeys } from '../dist/keys.js';
import { ERROR_CODES, StudioJwtError } from '../dist/errors.js';
import {
  generateTestRsaKeyPair,
  exportJwkFromPublicKeyPem,
  createTempKeyFile,
  startMockJwksServer,
} from './test-utils.js';

describe('verifyToken', () => {
  let testKeypair;
  let tempKey;
  let mockServer;
  let kid = 'auth-test-key-1';
  let verifyConfig;
  let signConfig;

  beforeEach(async () => {
    testKeypair = generateTestRsaKeyPair();
    tempKey = createTempKeyFile(testKeypair.privateKey);

    const jwk = exportJwkFromPublicKeyPem(testKeypair.publicKey, kid);
    mockServer = await startMockJwksServer({ keys: [jwk] });

    verifyConfig = {
      jwksUrl: mockServer.url,
      issuer: 'studio-auth',
      audience: 'studio-api',
    };

    signConfig = {
      privateKeyPath: tempKey.filePath,
      kid,
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
    if (tempKey) {
      tempKey.cleanup();
    }
    _resetKeys();
  });

  async function signHelper(claims = {}, options = {}) {
    const key = await importPKCS8(testKeypair.privateKey, 'RS256');
    const builder = new SignJWT({
      type: 'access',
      sub: 'test-subject',
      ...claims,
    })
      .setProtectedHeader({
        alg: options.alg || 'RS256',
        kid: options.kid !== undefined ? options.kid : kid,
        typ: 'JWT',
      })
      .setIssuer(options.issuer || 'studio-auth')
      .setAudience(options.audience || 'studio-api')
      .setIssuedAt(options.iat !== undefined ? options.iat : undefined);

    if (options.exp !== undefined) {
      builder.setExpirationTime(options.exp);
    } else {
      builder.setExpirationTime('15m');
    }

    return builder.sign(key);
  }

  it('successfully verifies a valid RS256 token and returns the payload using config parameter', async () => {
    const token = await signHelper({
      actor: 'SALON_USER',
      role: 'ADMIN',
      sid: 'session-123',
      did: 'device-456',
    });

    const payload = await verifyToken(token, verifyConfig);
    assert.equal(typeof payload, 'object');
    assert.equal(payload.sub, 'test-subject');
    assert.equal(payload.type, 'access');
    assert.equal(payload.actor, 'SALON_USER');
    assert.equal(payload.role, 'ADMIN');
    assert.equal(payload.sid, 'session-123');
    assert.equal(payload.did, 'device-456');
    assert.equal(payload.iss, 'studio-auth');
    assert.equal(payload.aud, 'studio-api');
    assert.ok(payload.exp > payload.iat);
  });

  it('verifies tokens created by createToken end-to-end', async () => {
    const token = await createToken(
      {
        sub: 'e2e-user',
        actor: 'COMPANY_STAFF',
        role: 'SUPER_ADMIN',
        sid: 'sess-e2e',
        did: 'dev-e2e',
      },
      signConfig,
    );

    const payload = await verifyToken(token, verifyConfig);
    assert.equal(payload.sub, 'e2e-user');
    assert.equal(payload.actor, 'COMPANY_STAFF');
    assert.equal(payload.role, 'SUPER_ADMIN');
    assert.equal(payload.type, 'access');
  });

  it('fails with CONFIG_ERROR when config parameter is missing or incomplete', async () => {
    const token = await signHelper();

    // Missing config
    await assert.rejects(
      async () => verifyToken(token),
      (err) => {
        assert.ok(err instanceof StudioJwtError);
        assert.equal(err.code, ERROR_CODES.CONFIG_ERROR);
        return true;
      },
    );

    // Missing jwksUrl
    await assert.rejects(
      async () => verifyToken(token, { ...verifyConfig, jwksUrl: '' }),
      (err) => {
        assert.equal(err.code, ERROR_CODES.CONFIG_ERROR);
        return true;
      },
    );

    // Invalid jwksUrl
    await assert.rejects(
      async () => verifyToken(token, { ...verifyConfig, jwksUrl: 'not-a-url' }),
      (err) => {
        assert.equal(err.code, ERROR_CODES.CONFIG_ERROR);
        return true;
      },
    );

    // Missing issuer
    await assert.rejects(
      async () => verifyToken(token, { ...verifyConfig, issuer: '' }),
      (err) => {
        assert.equal(err.code, ERROR_CODES.CONFIG_ERROR);
        return true;
      },
    );

    // Missing audience
    await assert.rejects(
      async () => verifyToken(token, { ...verifyConfig, audience: '' }),
      (err) => {
        assert.equal(err.code, ERROR_CODES.CONFIG_ERROR);
        return true;
      },
    );
  });

  it('rejects expired tokens with TOKEN_EXPIRED code', async () => {
    const expiredToken = await signHelper({}, { exp: '-10s' });

    await assert.rejects(
      async () => verifyToken(expiredToken, verifyConfig),
      (err) => {
        assert.ok(err instanceof StudioJwtError);
        assert.equal(err.code, ERROR_CODES.TOKEN_EXPIRED);
        assert.equal(err.category, 'CREDENTIALS');
        return true;
      },
    );
  });

  it('rejects malformed tokens with INVALID_TOKEN code', async () => {
    const malformed = [
      '',
      'not.a.valid.jwt.four.parts',
      'only-one-part',
      'invalid-base64.header.signature',
      12345,
      null,
      undefined,
    ];

    for (const t of malformed) {
      await assert.rejects(
        async () => verifyToken(t, verifyConfig),
        (err) => {
          assert.ok(err instanceof StudioJwtError);
          assert.equal(err.code, ERROR_CODES.INVALID_TOKEN);
          assert.equal(err.category, 'CREDENTIALS');
          return true;
        },
      );
    }
  });

  it('rejects tampered signature with INVALID_SIGNATURE code', async () => {
    const validToken = await signHelper();
    const parts = validToken.split('.');
    const tamperedSig = parts[2].slice(0, -4) + 'AAAA';
    const tamperedToken = `${parts[0]}.${parts[1]}.${tamperedSig}`;

    await assert.rejects(
      async () => verifyToken(tamperedToken, verifyConfig),
      (err) => {
        assert.ok(err instanceof StudioJwtError);
        assert.equal(err.code, ERROR_CODES.INVALID_SIGNATURE);
        assert.equal(err.category, 'CREDENTIALS');
        return true;
      },
    );
  });

  it('rejects tampered payload with INVALID_SIGNATURE code', async () => {
    const validToken = await signHelper();
    const parts = validToken.split('.');
    const tamperedPayload = Buffer.from(JSON.stringify({ sub: 'hacked', type: 'access' })).toString('base64url');
    const tamperedToken = `${parts[0]}.${tamperedPayload}.${parts[2]}`;

    await assert.rejects(
      async () => verifyToken(tamperedToken, verifyConfig),
      (err) => {
        assert.ok(err instanceof StudioJwtError);
        assert.equal(err.code, ERROR_CODES.INVALID_SIGNATURE);
        assert.equal(err.category, 'CREDENTIALS');
        return true;
      },
    );
  });

  it('rejects token signed by an untrusted key', async () => {
    const rogueKeypair = generateTestRsaKeyPair();
    const rogueKey = await importPKCS8(rogueKeypair.privateKey, 'RS256');

    const rogueToken = await new SignJWT({ sub: 'untrusted', type: 'access' })
      .setProtectedHeader({ alg: 'RS256', kid, typ: 'JWT' })
      .setIssuer('studio-auth')
      .setAudience('studio-api')
      .setExpirationTime('15m')
      .sign(rogueKey);

    await assert.rejects(
      async () => verifyToken(rogueToken, verifyConfig),
      (err) => {
        assert.ok(err instanceof StudioJwtError);
        assert.equal(err.code, ERROR_CODES.INVALID_SIGNATURE);
        return true;
      },
    );
  });

  it('rejects unsupported algorithm (none / HS256) with INVALID_ALGORITHM code', async () => {
    const noneHeader = Buffer.from(JSON.stringify({ alg: 'none', kid })).toString('base64url');
    const payload = Buffer.from(JSON.stringify({ sub: 'user-1', type: 'access' })).toString('base64url');
    const noneToken = `${noneHeader}.${payload}.`;

    await assert.rejects(
      async () => verifyToken(noneToken, verifyConfig),
      (err) => {
        assert.ok(err instanceof StudioJwtError);
        assert.equal(err.code, ERROR_CODES.INVALID_ALGORITHM);
        return true;
      },
    );

    const hsHeader = Buffer.from(JSON.stringify({ alg: 'HS256', kid })).toString('base64url');
    const hsToken = `${hsHeader}.${payload}.fakesig`;

    await assert.rejects(
      async () => verifyToken(hsToken, verifyConfig),
      (err) => {
        assert.ok(err instanceof StudioJwtError);
        assert.equal(err.code, ERROR_CODES.INVALID_ALGORITHM);
        return true;
      },
    );
  });

  it('rejects token with missing key ID (kid) in header', async () => {
    const tokenNoKid = await signHelper({}, { kid: null });

    await assert.rejects(
      async () => verifyToken(tokenNoKid, verifyConfig),
      (err) => {
        assert.ok(err instanceof StudioJwtError);
        assert.equal(err.code, ERROR_CODES.INVALID_TOKEN);
        assert.ok(err.message.includes('Missing or invalid key ID'));
        return true;
      },
    );
  });

  it('rejects invalid issuer with INVALID_CLAIMS code', async () => {
    const badIssuerToken = await signHelper({}, { issuer: 'untrusted-auth-service' });

    await assert.rejects(
      async () => verifyToken(badIssuerToken, verifyConfig),
      (err) => {
        assert.ok(err instanceof StudioJwtError);
        assert.equal(err.code, ERROR_CODES.INVALID_CLAIMS);
        return true;
      },
    );
  });

  it('rejects invalid audience with INVALID_CLAIMS code', async () => {
    const badAudToken = await signHelper({}, { audience: 'wrong-audience' });

    await assert.rejects(
      async () => verifyToken(badAudToken, verifyConfig),
      (err) => {
        assert.ok(err instanceof StudioJwtError);
        assert.equal(err.code, ERROR_CODES.INVALID_CLAIMS);
        return true;
      },
    );
  });

  it('rejects token when type claim is not "access"', async () => {
    const refreshTypeToken = await signHelper({ type: 'refresh' });

    await assert.rejects(
      async () => verifyToken(refreshTypeToken, verifyConfig),
      (err) => {
        assert.ok(err instanceof StudioJwtError);
        assert.equal(err.code, ERROR_CODES.INVALID_CLAIMS);
        assert.ok(err.message.includes('expected access token'));
        return true;
      },
    );
  });

  it('rejects token when sub claim is missing or empty', async () => {
    const emptySubToken = await signHelper({ sub: '' });

    await assert.rejects(
      async () => verifyToken(emptySubToken, verifyConfig),
      (err) => {
        assert.ok(err instanceof StudioJwtError);
        assert.equal(err.code, ERROR_CODES.INVALID_CLAIMS);
        return true;
      },
    );
  });

  it('rejects unknown key ID with UNKNOWN_KID code', async () => {
    const unknownKidToken = await signHelper({}, { kid: 'non-existent-kid-999' });

    await assert.rejects(
      async () => verifyToken(unknownKidToken, verifyConfig),
      (err) => {
        assert.ok(err instanceof StudioJwtError);
        assert.equal(err.code, ERROR_CODES.UNKNOWN_KID);
        assert.equal(err.category, 'CREDENTIALS');
        return true;
      },
    );
  });

  it('fails with JWKS_UNAVAILABLE when JWKS endpoint returns HTTP 500', async () => {
    mockServer.setStatusCode(500);

    const token = await signHelper();

    await assert.rejects(
      async () => verifyToken(token, verifyConfig),
      (err) => {
        assert.ok(err instanceof StudioJwtError);
        assert.equal(err.code, ERROR_CODES.JWKS_UNAVAILABLE);
        assert.equal(err.category, 'INFRASTRUCTURE');
        return true;
      },
    );
  });

  it('fails with JWKS_UNAVAILABLE when JWKS endpoint is unreachable', async () => {
    const unreachableConfig = {
      ...verifyConfig,
      jwksUrl: 'http://127.0.0.1:19991/unreachable/jwks.json',
    };

    const token = await signHelper();

    await assert.rejects(
      async () => verifyToken(token, unreachableConfig),
      (err) => {
        assert.ok(err instanceof StudioJwtError);
        assert.equal(err.code, ERROR_CODES.JWKS_UNAVAILABLE);
        assert.equal(err.category, 'INFRASTRUCTURE');
        return true;
      },
    );
  });

  it('respects clock tolerance for borderline expirations', async () => {
    const nowSec = Math.floor(Date.now() / 1000);
    const key = await importPKCS8(testKeypair.privateKey, 'RS256');

    const token = await new SignJWT({ sub: 'clock-user', type: 'access' })
      .setProtectedHeader({ alg: 'RS256', kid, typ: 'JWT' })
      .setIssuer('studio-auth')
      .setAudience('studio-api')
      .setIssuedAt(nowSec - 100)
      .setExpirationTime(nowSec - 2) // expired 2 seconds ago
      .sign(key);

    const payload = await verifyToken(token, { ...verifyConfig, clockTolerance: 5 });
    assert.equal(payload.sub, 'clock-user');
  });
});
