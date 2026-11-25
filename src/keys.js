import fs from 'node:fs/promises';
import path from 'node:path';
import crypto from 'node:crypto';
import { importPKCS8, createRemoteJWKSet } from 'jose';
import { createKeyLoadError } from './errors.js';

const privateKeyCache = new Map();
const pendingKeyPromises = new Map();
const jwksResolvers = new Map();

export async function getPrivateKey(config) {
  const cacheKey = config.privateKeyPath || `${config.kid}:${config.privateKey}`;

  if (privateKeyCache.has(cacheKey)) {
    return privateKeyCache.get(cacheKey);
  }
  if (pendingKeyPromises.has(cacheKey)) {
    return pendingKeyPromises.get(cacheKey);
  }

  const promise = (async () => {
    try {
      let pem = config.privateKey;
      if (!pem && config.privateKeyPath) {
        const resolvedPath = path.isAbsolute(config.privateKeyPath)
          ? config.privateKeyPath
          : path.resolve(process.cwd(), config.privateKeyPath);

        try {
          pem = await fs.readFile(resolvedPath, 'utf8');
        } catch (err) {
          throw createKeyLoadError(`Failed to read private key at ${resolvedPath}: ${err.message}`, err);
        }
      }

      pem = (pem || '').trim();
      if (!pem.includes('BEGIN') || !pem.includes('PRIVATE KEY')) {
        throw createKeyLoadError('Private key is not a valid PEM format');
      }

      let pkcs8Pem = pem;
      if (pem.includes('BEGIN RSA PRIVATE KEY')) {
        try {
          const keyObject = crypto.createPrivateKey(pem);
          pkcs8Pem = keyObject.export({ type: 'pkcs8', format: 'pem' });
        } catch (err) {
          throw createKeyLoadError(`Failed to parse RSA private key: ${err.message}`, err);
        }
      }

      let importedKey;
      try {
        importedKey = await importPKCS8(pkcs8Pem, 'RS256');
      } catch (err) {
        throw createKeyLoadError(`Failed to import private key: ${err.message}`, err);
      }

      privateKeyCache.set(cacheKey, importedKey);
      return importedKey;
    } finally {
      pendingKeyPromises.delete(cacheKey);
    }
  })();

  pendingKeyPromises.set(cacheKey, promise);
  return promise;
}

export function getJwksResolver(config) {
  const url = config.jwksUrl;
  let resolver = jwksResolvers.get(url);

  if (!resolver) {
    resolver = createRemoteJWKSet(new URL(url), {
      cacheMaxAge: 10 * 60 * 1000,
      cooldownDuration: config.cooldownDuration !== undefined ? config.cooldownDuration : 30 * 1000,
      timeoutDuration: 5 * 1000,
    });
    jwksResolvers.set(url, resolver);
  }

  return resolver;
}

export function _resetKeys() {
  privateKeyCache.clear();
  pendingKeyPromises.clear();
  jwksResolvers.clear();
}
