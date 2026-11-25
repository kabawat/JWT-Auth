import type { JWTPayload } from 'jose';
import type { KeyObject } from 'node:crypto';

export type KeyLike = KeyObject | CryptoKey | Uint8Array;

export interface SignConfig {
  privateKey?: string;
  privateKeyPath?: string;
  kid: string;
  issuer: string;
  audience: string;
  expiresIn: string | number;
  algorithm?: 'RS256';
}

export interface VerifyConfig {
  jwksUrl: string;
  issuer: string;
  audience: string;
  clockTolerance?: number;
  cooldownDuration?: number;
  algorithm?: 'RS256';
}

export interface CustomClaims {
  sub: string;
  type?: 'access';
  actor?: string;
  role?: string;
  sid?: string;
  did?: string;
  [key: string]: unknown;
}

export type ValidatedSignConfig = Readonly<{
  privateKey: string;
  privateKeyPath: string;
  kid: string;
  issuer: string;
  audience: string;
  expiresIn: string;
  algorithm: 'RS256';
}>;

export type ValidatedVerifyConfig = Readonly<{
  jwksUrl: string;
  issuer: string;
  audience: string;
  clockTolerance: number;
  cooldownDuration: number;
  algorithm: 'RS256';
}>;

export type VerifiedJwtPayload = JWTPayload & CustomClaims;
