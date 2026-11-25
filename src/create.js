import { SignJWT } from 'jose';
import { validateSignConfig } from './config.js';
import { getPrivateKey } from './keys.js';
import { createInvalidClaimsError } from './errors.js';

const PROTECTED_CLAIMS = new Set(['iss', 'aud', 'exp', 'iat', 'nbf', 'jti', 'alg', 'kid']);

export async function createToken(payload, config) {
  if (!payload || typeof payload !== 'object' || Array.isArray(payload)) {
    throw createInvalidClaimsError('Token payload must be a non-null object');
  }

  for (const claim of Object.keys(payload)) {
    if (PROTECTED_CLAIMS.has(claim)) {
      throw createInvalidClaimsError(`Cannot override protected claim: ${claim}`);
    }
  }

  if (payload.type !== undefined && payload.type !== 'access') {
    throw createInvalidClaimsError('Invalid token type: only access tokens are supported');
  }

  if (!payload.sub || typeof payload.sub !== 'string' || payload.sub.trim() === '') {
    throw createInvalidClaimsError('Subject (sub) claim is required and must be a non-empty string');
  }

  if (payload.actor !== undefined && (typeof payload.actor !== 'string' || payload.actor.trim() === '')) {
    throw createInvalidClaimsError('Actor claim must be a non-empty string when provided');
  }

  if (payload.role !== undefined && (typeof payload.role !== 'string' || payload.role.trim() === '')) {
    throw createInvalidClaimsError('Role claim must be a non-empty string when provided');
  }

  if (payload.sid !== undefined && (typeof payload.sid !== 'string' || payload.sid.trim() === '')) {
    throw createInvalidClaimsError('Session ID (sid) claim must be a non-empty string when provided');
  }

  if (payload.did !== undefined && (typeof payload.did !== 'string' || payload.did.trim() === '')) {
    throw createInvalidClaimsError('Device ID (did) claim must be a non-empty string when provided');
  }

  const validConfig = validateSignConfig(config);
  const privateKey = await getPrivateKey(validConfig);

  const claims = { ...payload, type: 'access' };

  return new SignJWT(claims)
    .setProtectedHeader({ alg: 'RS256', kid: validConfig.kid, typ: 'JWT' })
    .setIssuer(validConfig.issuer)
    .setAudience(validConfig.audience)
    .setIssuedAt()
    .setExpirationTime(validConfig.expiresIn)
    .sign(privateKey);
}
