export class StudioJwtError extends Error {
  /**
   * @param {string} message
   * @param {string} code
   * @param {{ cause?: unknown, category?: 'CREDENTIALS' | 'INFRASTRUCTURE' }} [options]
   */
  constructor(message, code, options = {}) {
    super(message);
    this.name = 'StudioJwtError';
    this.code = code;
    this.category = options.category || 'CREDENTIALS';
    this.isOperational = true;
    if (options.cause !== undefined) {
      this.cause = options.cause;
    }
  }
}

export const ERROR_CODES = Object.freeze({
  CONFIG_ERROR: 'CONFIG_ERROR',
  PRIVATE_KEY_LOAD_ERROR: 'PRIVATE_KEY_LOAD_ERROR',
  JWKS_UNAVAILABLE: 'JWKS_UNAVAILABLE',
  INVALID_TOKEN: 'INVALID_TOKEN',
  TOKEN_EXPIRED: 'TOKEN_EXPIRED',
  INVALID_SIGNATURE: 'INVALID_SIGNATURE',
  INVALID_CLAIMS: 'INVALID_CLAIMS',
  UNKNOWN_KID: 'UNKNOWN_KID',
  INVALID_ALGORITHM: 'INVALID_ALGORITHM',
});

export function createConfigError(message, cause) {
  return new StudioJwtError(message, ERROR_CODES.CONFIG_ERROR, {
    category: 'INFRASTRUCTURE',
    cause,
  });
}

export function createKeyLoadError(message, cause) {
  return new StudioJwtError(message, ERROR_CODES.PRIVATE_KEY_LOAD_ERROR, {
    category: 'INFRASTRUCTURE',
    cause,
  });
}

export function createJwksUnavailableError(message, cause) {
  return new StudioJwtError(message, ERROR_CODES.JWKS_UNAVAILABLE, {
    category: 'INFRASTRUCTURE',
    cause,
  });
}

export function createInvalidTokenError(message, cause) {
  return new StudioJwtError(message, ERROR_CODES.INVALID_TOKEN, {
    category: 'CREDENTIALS',
    cause,
  });
}

export function createTokenExpiredError(message, cause) {
  return new StudioJwtError(message, ERROR_CODES.TOKEN_EXPIRED, {
    category: 'CREDENTIALS',
    cause,
  });
}

export function createInvalidSignatureError(message, cause) {
  return new StudioJwtError(message, ERROR_CODES.INVALID_SIGNATURE, {
    category: 'CREDENTIALS',
    cause,
  });
}

export function createInvalidClaimsError(message, cause) {
  return new StudioJwtError(message, ERROR_CODES.INVALID_CLAIMS, {
    category: 'CREDENTIALS',
    cause,
  });
}

export function createUnknownKidError(message, cause) {
  return new StudioJwtError(message, ERROR_CODES.UNKNOWN_KID, {
    category: 'CREDENTIALS',
    cause,
  });
}

export function createInvalidAlgorithmError(message, cause) {
  return new StudioJwtError(message, ERROR_CODES.INVALID_ALGORITHM, {
    category: 'CREDENTIALS',
    cause,
  });
}
