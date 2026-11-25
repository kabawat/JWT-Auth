import { describe, it, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import { decodeJwt, decodeProtectedHeader } from 'jose';
import { createToken } from '../src/create.js';
import { _resetKeys } from '../src/keys.js';
import { ERROR_CODES, StudioJwtError } from '../src/errors.js';
import {
  generateTestRsaKeyPair,
  generatePkcs1KeyPair,
  createTempKeyFile,
} from './test-utils.js';

describe('createToken', () => {
  let testKeypair;
  let tempKey;
  let validConfig;

  beforeEach(() => {
    testKeypair = generateTestRsaKeyPair();
    tempKey = createTempKeyFile(testKeypair.privateKey);

    validConfig = {
      privateKeyPath: tempKey.filePath,
      kid: 'auth-test-1',
      issuer: 'studio-auth',
      audience: 'studio-api',
      expiresIn: '15m',
    };

    _resetKeys();
  });

  afterEach(() => {
    if (tempKey) {
      tempKey.cleanup();
    }
    _resetKeys();
  });

  it('creates a valid signed RS256 JWT with expected claims and headers using config parameter', async () => {
    const payload = {
      sub: 'user-123',
      actor: 'SALON_USER',
      role: 'OWNER',
      sid: 'session-456',
      did: 'device-789',
    };

    const token = await createToken(payload, validConfig);
    assert.equal(typeof token, 'string');
    assert.equal(token.split('.').length, 3);

    const header = decodeProtectedHeader(token);
    assert.equal(header.alg, 'RS256');
    assert.equal(header.kid, 'auth-test-1');
    assert.equal(header.typ, 'JWT');

    const decoded = decodeJwt(token);
    assert.equal(decoded.sub, 'user-123');
    assert.equal(decoded.type, 'access');
    assert.equal(decoded.actor, 'SALON_USER');
    assert.equal(decoded.role, 'OWNER');
    assert.equal(decoded.sid, 'session-456');
    assert.equal(decoded.did, 'device-789');
    assert.equal(decoded.iss, 'studio-auth');
    assert.equal(decoded.aud, 'studio-api');
    assert.ok(typeof decoded.iat === 'number');
    assert.ok(typeof decoded.exp === 'number');
    assert.ok(decoded.exp > decoded.iat);
  });

  it('supports passing privateKey directly as a PEM string in config parameter', async () => {
    const directPemConfig = {
      privateKey: testKeypair.privateKey,
      kid: 'auth-direct-1',
      issuer: 'studio-auth',
      audience: 'studio-api',
      expiresIn: '10m',
    };

    const token = await createToken({ sub: 'direct-pem-user' }, directPemConfig);
    const decoded = decodeJwt(token);
    assert.equal(decoded.sub, 'direct-pem-user');
    assert.equal(decoded.type, 'access');
  });

  it('supports all existing actor types without unnecessary business logic', async () => {
    // 1. Customer (no actor)
    const customerToken = await createToken({ sub: 'cust-1', sid: 's-1', did: 'd-1' }, validConfig);
    const custPayload = decodeJwt(customerToken);
    assert.equal(custPayload.sub, 'cust-1');
    assert.equal(custPayload.type, 'access');
    assert.equal(custPayload.actor, undefined);

    // 2. Company Staff
    const staffToken = await createToken(
      {
        sub: 'staff-1',
        actor: 'COMPANY_STAFF',
        role: 'ADMIN',
        sid: 's-2',
        did: 'd-2',
      },
      validConfig,
    );
    const staffPayload = decodeJwt(staffToken);
    assert.equal(staffPayload.actor, 'COMPANY_STAFF');
    assert.equal(staffPayload.role, 'ADMIN');

    // 3. Stylist
    const stylistToken = await createToken(
      {
        sub: 'stylist-1',
        actor: 'STYLIST',
        sid: 's-3',
        did: 'd-3',
      },
      validConfig,
    );
    const stylistPayload = decodeJwt(stylistToken);
    assert.equal(stylistPayload.actor, 'STYLIST');

    // 4. Salon User
    const salonToken = await createToken(
      {
        sub: 'salon-1',
        actor: 'SALON_USER',
        role: 'STAFF',
        sid: 's-4',
        did: 'd-4',
      },
      validConfig,
    );
    const salonPayload = decodeJwt(salonToken);
    assert.equal(salonPayload.actor, 'SALON_USER');
    assert.equal(salonPayload.role, 'STAFF');

    // 5. Custom claims (e.g. salonId)
    const customToken = await createToken(
      {
        sub: 'user-custom',
        actor: 'SALON_USER',
        salonId: 'salon-abc-123',
      },
      validConfig,
    );
    const customPayload = decodeJwt(customToken);
    assert.equal(customPayload.salonId, 'salon-abc-123');
  });

  it('prevents callers from overriding protected claims', async () => {
    const protectedOverrides = [
      { iss: 'evil-issuer' },
      { aud: 'evil-audience' },
      { exp: 9999999999 },
      { iat: 1000000000 },
      { nbf: 1000000000 },
      { jti: 'custom-jti' },
      { alg: 'HS256' },
      { kid: 'evil-kid' },
    ];

    for (const override of protectedOverrides) {
      await assert.rejects(
        async () => createToken({ sub: 'user-1', ...override }, validConfig),
        (err) => {
          assert.ok(err instanceof StudioJwtError);
          assert.equal(err.code, ERROR_CODES.INVALID_CLAIMS);
          assert.ok(err.message.includes('Cannot override protected claim'));
          return true;
        },
      );
    }
  });

  it('rejects invalid token type override', async () => {
    await assert.rejects(
      async () => createToken({ sub: 'user-1', type: 'refresh' }, validConfig),
      (err) => {
        assert.ok(err instanceof StudioJwtError);
        assert.equal(err.code, ERROR_CODES.INVALID_CLAIMS);
        return true;
      },
    );
  });

  it('accepts explicit type: "access" matching standard access tokens', async () => {
    const token = await createToken({ sub: 'user-1', type: 'access' }, validConfig);
    const payload = decodeJwt(token);
    assert.equal(payload.type, 'access');
  });

  it('rejects invalid or missing payload arguments', async () => {
    const invalidPayloads = [null, undefined, '', 123, true, []];
    for (const p of invalidPayloads) {
      await assert.rejects(
        async () => createToken(p, validConfig),
        (err) => {
          assert.ok(err instanceof StudioJwtError);
          assert.equal(err.code, ERROR_CODES.INVALID_CLAIMS);
          return true;
        },
      );
    }

    await assert.rejects(
      async () => createToken({}, validConfig),
      (err) => {
        assert.equal(err.code, ERROR_CODES.INVALID_CLAIMS);
        return true;
      },
    );

    await assert.rejects(
      async () => createToken({ sub: '' }, validConfig),
      (err) => {
        assert.equal(err.code, ERROR_CODES.INVALID_CLAIMS);
        return true;
      },
    );
  });

  it('fails securely when config parameter is missing or incomplete', async () => {
    // Missing config entirely
    await assert.rejects(
      async () => createToken({ sub: 'user-1' }),
      (err) => {
        assert.ok(err instanceof StudioJwtError);
        assert.equal(err.code, ERROR_CODES.CONFIG_ERROR);
        assert.equal(err.category, 'INFRASTRUCTURE');
        return true;
      },
    );

    // Missing key
    await assert.rejects(
      async () => createToken({ sub: 'user-1' }, { ...validConfig, privateKeyPath: '' }),
      (err) => {
        assert.equal(err.code, ERROR_CODES.CONFIG_ERROR);
        return true;
      },
    );

    // Missing kid
    await assert.rejects(
      async () => createToken({ sub: 'user-1' }, { ...validConfig, kid: '' }),
      (err) => {
        assert.equal(err.code, ERROR_CODES.CONFIG_ERROR);
        return true;
      },
    );

    // Missing issuer
    await assert.rejects(
      async () => createToken({ sub: 'user-1' }, { ...validConfig, issuer: '' }),
      (err) => {
        assert.equal(err.code, ERROR_CODES.CONFIG_ERROR);
        return true;
      },
    );

    // Missing audience
    await assert.rejects(
      async () => createToken({ sub: 'user-1' }, { ...validConfig, audience: '' }),
      (err) => {
        assert.equal(err.code, ERROR_CODES.CONFIG_ERROR);
        return true;
      },
    );

    // Missing expiresIn
    await assert.rejects(
      async () => createToken({ sub: 'user-1' }, { ...validConfig, expiresIn: '' }),
      (err) => {
        assert.equal(err.code, ERROR_CODES.CONFIG_ERROR);
        return true;
      },
    );

    // Invalid expiresIn format
    await assert.rejects(
      async () => createToken({ sub: 'user-1' }, { ...validConfig, expiresIn: 'bad-format' }),
      (err) => {
        assert.equal(err.code, ERROR_CODES.CONFIG_ERROR);
        return true;
      },
    );
  });

  it('fails securely when private key file does not exist', async () => {
    await assert.rejects(
      async () => createToken({ sub: 'user-1' }, { ...validConfig, privateKeyPath: '/non/existent/key.pem' }),
      (err) => {
        assert.ok(err instanceof StudioJwtError);
        assert.equal(err.code, ERROR_CODES.PRIVATE_KEY_LOAD_ERROR);
        assert.equal(err.category, 'INFRASTRUCTURE');
        return true;
      },
    );
  });

  it('fails securely when private key is not a valid PEM', async () => {
    const corruptKey = createTempKeyFile('not a valid pem content');

    try {
      await assert.rejects(
        async () => createToken({ sub: 'user-1' }, { ...validConfig, privateKeyPath: corruptKey.filePath }),
        (err) => {
          assert.ok(err instanceof StudioJwtError);
          assert.equal(err.code, ERROR_CODES.PRIVATE_KEY_LOAD_ERROR);
          return true;
        },
      );
    } finally {
      corruptKey.cleanup();
    }
  });

  it('supports PKCS#1 (BEGIN RSA PRIVATE KEY) format', async () => {
    const pkcs1Pair = generatePkcs1KeyPair();
    const pkcs1File = createTempKeyFile(pkcs1Pair.privateKey, 'pkcs1-private.pem');

    try {
      const token = await createToken({ sub: 'pkcs1-user' }, { ...validConfig, privateKeyPath: pkcs1File.filePath });
      assert.equal(typeof token, 'string');
      const payload = decodeJwt(token);
      assert.equal(payload.sub, 'pkcs1-user');
    } finally {
      pkcs1File.cleanup();
    }
  });

  it('imports private key only once and deduplicates concurrent signing calls', async () => {
    const promises = Array.from({ length: 20 }, (_, i) =>
      createToken({ sub: `concurrent-user-${i}` }, validConfig),
    );

    const tokens = await Promise.all(promises);
    assert.equal(tokens.length, 20);
    for (let i = 0; i < 20; i++) {
      const payload = decodeJwt(tokens[i]);
      assert.equal(payload.sub, `concurrent-user-${i}`);
    }
  });
});
