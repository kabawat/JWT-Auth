import { jwtVerify, decodeProtectedHeader, errors } from 'jose';
import { validateVerifyConfig } from './config.js';
import { getJwksResolver } from './keys.js';
import {
  StudioJwtError,
  createInvalidTokenError,
  createTokenExpiredError,
  createInvalidSignatureError,
  createInvalidClaimsError,
  createUnknownKidError,
  createInvalidAlgorithmError,
  createJwksUnavailableError,
} from './errors.js';

export async function verifyToken(token, config) {
  if (!token || typeof token !== 'string') {
    throw createInvalidTokenError('Token must be a non-empty string');
  }

  const parts = token.split('.');
  if (parts.length !== 3) {
    throw createInvalidTokenError('Malformed JWT: token must contain 3 dot-separated segments');
  }

  let header;
  try {
    header = decodeProtectedHeader(token);
  } catch (err) {
    throw createInvalidTokenError('Malformed JWT header', err);
  }

  if (!header || typeof header !== 'object') {
    throw createInvalidTokenError('Malformed JWT header');
  }

  if (header.alg !== 'RS256') {
    throw createInvalidAlgorithmError(`Unsupported algorithm: ${header.alg}. Only RS256 is supported`);
  }

  if (!header.kid || typeof header.kid !== 'string' || header.kid.trim() === '') {
    throw createInvalidTokenError('Missing or invalid key ID (kid) in token header');
  }

  const validConfig = validateVerifyConfig(config);
  const jwksResolver = getJwksResolver(validConfig);

  let verifiedPayload;
  try {
    const result = await jwtVerify(token, jwksResolver, {
      issuer: validConfig.issuer,
      audience: validConfig.audience,
      algorithms: ['RS256'],
      clockTolerance: validConfig.clockTolerance,
    });
    verifiedPayload = result.payload;
  } catch (err) {
    if (err instanceof errors.JWTExpired) {
      throw createTokenExpiredError('Token has expired', err);
    }
    if (err instanceof errors.JWSSignatureVerificationFailed) {
      throw createInvalidSignatureError('Invalid token signature', err);
    }
    if (err instanceof errors.JOSEAlgNotAllowed || err instanceof errors.JOSENotSupported) {
      throw createInvalidAlgorithmError('Invalid or unsupported algorithm', err);
    }
    if (err instanceof errors.JWTClaimValidationFailed) {
      throw createInvalidClaimsError(`Token claim validation failed for claim: ${err.claim}`, err);
    }
    if (err instanceof errors.JWKSNoMatchingKey) {
      throw createUnknownKidError(`Unknown key ID: key "${header.kid}" not found in JWKS`, err);
    }
    if (err instanceof errors.JWKSTimeout) {
      throw createJwksUnavailableError('JWKS request timed out', err);
    }
    if (
      err instanceof errors.JWKSInvalid
      || (err.message && err.message.includes('fetch failed'))
      || (err.message && err.message.includes('JSON Web Key Set'))
      || (err.cause && (err.cause.code === 'ECONNREFUSED' || err.cause.code === 'ENOTFOUND'))
    ) {
      throw createJwksUnavailableError('JWKS endpoint unavailable or unreachable', err);
    }
    if (err instanceof errors.JWTInvalid || err instanceof errors.JWSInvalid) {
      throw createInvalidTokenError('Invalid token structure', err);
    }
    if (err instanceof StudioJwtError) {
      throw err;
    }
    throw createInvalidTokenError(`Token verification failed: ${err.message}`, err);
  }

  if (!verifiedPayload || typeof verifiedPayload !== 'object') {
    throw createInvalidClaimsError('Invalid token payload: expected object');
  }

  if (verifiedPayload.type !== 'access') {
    throw createInvalidClaimsError('Invalid token type: expected access token');
  }

  if (!verifiedPayload.sub || typeof verifiedPayload.sub !== 'string' || verifiedPayload.sub.trim() === '') {
    throw createInvalidClaimsError('Missing or invalid sub claim in verified token');
  }

  return verifiedPayload;
}
