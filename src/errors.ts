export type ErrorCategory = 'CREDENTIALS' | 'INFRASTRUCTURE';

export interface ErrorOptions {
  cause?: unknown;
  category?: ErrorCategory;
}

export class StudioJwtError extends Error {
  readonly code: string;
  readonly category: ErrorCategory;
  readonly isOperational: boolean;
  readonly cause?: unknown;

  constructor(message: string, code: string, options: ErrorOptions = {}) {
    super(message);
    this.name = 'StudioJwtError';
    this.code = code;
    this.category = options.category || 'CREDENTIALS';
    this.isOperational = true;
    if (options.cause !== undefined) {
      this.cause = options.cause;
    }
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

export const JwtAuthError = StudioJwtError;

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
} as const);

export type ErrorCode = typeof ERROR_CODES[keyof typeof ERROR_CODES];

export function createConfigError(message: string, cause?: unknown): StudioJwtError {
  return new StudioJwtError(message, ERROR_CODES.CONFIG_ERROR, {
    category: 'INFRASTRUCTURE',
    cause,
  });
}

export function createKeyLoadError(message: string, cause?: unknown): StudioJwtError {
  return new StudioJwtError(message, ERROR_CODES.PRIVATE_KEY_LOAD_ERROR, {
    category: 'INFRASTRUCTURE',
    cause,
  });
}

export function createJwksUnavailableError(message: string, cause?: unknown): StudioJwtError {
  return new StudioJwtError(message, ERROR_CODES.JWKS_UNAVAILABLE, {
    category: 'INFRASTRUCTURE',
    cause,
  });
}

export function createInvalidTokenError(message: string, cause?: unknown): StudioJwtError {
  return new StudioJwtError(message, ERROR_CODES.INVALID_TOKEN, {
    category: 'CREDENTIALS',
    cause,
  });
}

export function createTokenExpiredError(message: string, cause?: unknown): StudioJwtError {
  return new StudioJwtError(message, ERROR_CODES.TOKEN_EXPIRED, {
    category: 'CREDENTIALS',
    cause,
  });
}

export function createInvalidSignatureError(message: string, cause?: unknown): StudioJwtError {
  return new StudioJwtError(message, ERROR_CODES.INVALID_SIGNATURE, {
    category: 'CREDENTIALS',
    cause,
  });
}

export function createInvalidClaimsError(message: string, cause?: unknown): StudioJwtError {
  return new StudioJwtError(message, ERROR_CODES.INVALID_CLAIMS, {
    category: 'CREDENTIALS',
    cause,
  });
}

export function createUnknownKidError(message: string, cause?: unknown): StudioJwtError {
  return new StudioJwtError(message, ERROR_CODES.UNKNOWN_KID, {
    category: 'CREDENTIALS',
    cause,
  });
}

export function createInvalidAlgorithmError(message: string, cause?: unknown): StudioJwtError {
  return new StudioJwtError(message, ERROR_CODES.INVALID_ALGORITHM, {
    category: 'CREDENTIALS',
    cause,
  });
}
