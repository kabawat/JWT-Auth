import { createConfigError } from './errors.js';
import type { ValidatedSignConfig, ValidatedVerifyConfig } from './types.js';

const DURATION_REGEX = /^(\d+)([smhdwy]?)$/;

export function validateSignConfig(config: unknown): ValidatedSignConfig {
  if (!config || typeof config !== 'object' || Array.isArray(config)) {
    throw createConfigError('Sign configuration object is required');
  }

  const c = config as Record<string, unknown>;
  const privateKey = typeof c.privateKey === 'string' ? c.privateKey.trim() : '';
  const privateKeyPath = typeof c.privateKeyPath === 'string' ? c.privateKeyPath.trim() : '';
  const kid = typeof c.kid === 'string' ? c.kid.trim() : '';
  const issuer = typeof c.issuer === 'string' ? c.issuer.trim() : '';
  const audience = typeof c.audience === 'string' ? c.audience.trim() : '';
  const expiresIn = typeof c.expiresIn === 'string'
    ? c.expiresIn.trim()
    : (typeof c.expiresIn === 'number' ? String(c.expiresIn) : '');

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
    algorithm: 'RS256' as const,
  });
}

export function validateVerifyConfig(config: unknown): ValidatedVerifyConfig {
  if (!config || typeof config !== 'object' || Array.isArray(config)) {
    throw createConfigError('Verify configuration object is required');
  }

  const c = config as Record<string, unknown>;
  const jwksUrl = typeof c.jwksUrl === 'string' ? c.jwksUrl.trim() : '';
  const issuer = typeof c.issuer === 'string' ? c.issuer.trim() : '';
  const audience = typeof c.audience === 'string' ? c.audience.trim() : '';
  const clockTolerance = typeof c.clockTolerance === 'number' && c.clockTolerance >= 0
    ? c.clockTolerance
    : 5;
  const cooldownDuration = typeof c.cooldownDuration === 'number' && c.cooldownDuration >= 0
    ? c.cooldownDuration
    : 30000;

  if (!jwksUrl) {
    throw createConfigError('jwksUrl is required in configuration');
  }

  try {
    const parsed = new URL(jwksUrl);
    if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
      throw new Error('Protocol must be http: or https:');
    }
  } catch (err: any) {
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
    algorithm: 'RS256' as const,
  });
}
