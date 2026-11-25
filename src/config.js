import { createConfigError } from './errors.js';

const DURATION_REGEX = /^(\d+)([smhdwy]?)$/;

export function validateSignConfig(config) {
  if (!config || typeof config !== 'object' || Array.isArray(config)) {
    throw createConfigError('Sign configuration object is required');
  }

  const privateKey = typeof config.privateKey === 'string' ? config.privateKey.trim() : '';
  const privateKeyPath = typeof config.privateKeyPath === 'string' ? config.privateKeyPath.trim() : '';
  const kid = typeof config.kid === 'string' ? config.kid.trim() : '';
  const issuer = typeof config.issuer === 'string' ? config.issuer.trim() : '';
  const audience = typeof config.audience === 'string' ? config.audience.trim() : '';
  const expiresIn = typeof config.expiresIn === 'string'
    ? config.expiresIn.trim()
    : (typeof config.expiresIn === 'number' ? String(config.expiresIn) : '');

  if (!privateKey && !privateKeyPath) {
    throw createConfigError('privateKey (PEM string) or privateKeyPath is required in configuration');
  }
  if (!kid) {
    throw createConfigError('kid is required in configuration');
  }
  if (!issuer) {
    throw createConfigError('issuer is required in configuration');
  }
  if (!audience) {
    throw createConfigError('audience is required in configuration');
  }
  if (!expiresIn) {
    throw createConfigError('expiresIn is required in configuration');
  }
  if (!DURATION_REGEX.test(expiresIn)) {
    throw createConfigError(`Invalid expiresIn format: "${expiresIn}". Expected e.g. 15m, 1h, 300s`);
  }

  return Object.freeze({
    privateKey,
    privateKeyPath,
    kid,
    issuer,
    audience,
    expiresIn,
    algorithm: 'RS256',
  });
}

export function validateVerifyConfig(config) {
  if (!config || typeof config !== 'object' || Array.isArray(config)) {
    throw createConfigError('Verify configuration object is required');
  }

  const jwksUrl = typeof config.jwksUrl === 'string' ? config.jwksUrl.trim() : '';
  const issuer = typeof config.issuer === 'string' ? config.issuer.trim() : '';
  const audience = typeof config.audience === 'string' ? config.audience.trim() : '';
  const clockTolerance = typeof config.clockTolerance === 'number' && config.clockTolerance >= 0
    ? config.clockTolerance
    : 5;
  const cooldownDuration = typeof config.cooldownDuration === 'number' && config.cooldownDuration >= 0
    ? config.cooldownDuration
    : 30000;

  if (!jwksUrl) {
    throw createConfigError('jwksUrl is required in configuration');
  }

  try {
    const parsed = new URL(jwksUrl);
    if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
      throw new Error('Protocol must be http: or https:');
    }
  } catch (err) {
    throw createConfigError(`Invalid jwksUrl: ${err.message}`, err);
  }

  if (!issuer) {
    throw createConfigError('issuer is required in configuration');
  }
  if (!audience) {
    throw createConfigError('audience is required in configuration');
  }

  return Object.freeze({
    jwksUrl,
    issuer,
    audience,
    clockTolerance,
    cooldownDuration,
    algorithm: 'RS256',
  });
}
