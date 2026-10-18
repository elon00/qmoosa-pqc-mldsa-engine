/**
 * QMOOSA Post-Quantum Cryptography — NIST FIPS 204 ML-DSA Signature Engine
 *
 * Provides cryptographic signing, verification, and key generation for ML-DSA-44,
 * ML-DSA-65, and ML-DSA-87.
 *
 * Production cryptographic execution delegates directly to the audited `@noble/post-quantum/ml-dsa.js`
 * library. Algorithmic polynomial ring arithmetic is preserved for pedagogical verification
 * in `reference-dilithium-math.ts`.
 */

import { randomBytes } from 'node:crypto';
import { ml_dsa44, ml_dsa65, ml_dsa87 } from '@noble/post-quantum/ml-dsa.js';
import {
  ML_DSA_44,
  ML_DSA_65,
  ML_DSA_87,
  getMlDsaParameters,
  validatePublicKey,
  validateSecretKey,
  validateSignature,
  constantTimeEqual,
  type MlDsaParameterName,
  type MlDsaParameters,
  type MlDsaKeyPair,
  type MlDsaSignatureResult
} from '@qmoosa/pqc-mldsa-protocol';

export * as ReferenceDilithiumMath from './reference-dilithium-math.js';

export interface KeyGenOptions {
  /**
   * 32-byte deterministic seed xi per NIST FIPS 204 Algorithm 1 (KeyGen).
   * If omitted, 32 cryptographically secure random bytes are sampled from the OS CSPRNG.
   */
  readonly seed?: Uint8Array;
}

export interface SignOptions {
  /**
   * Optional context string (max 255 bytes) for domain separation per NIST FIPS 204 Section 5.
   */
  readonly context?: Uint8Array | string;
  /**
   * Optional extra entropy (32 bytes) for non-deterministic randomized signing per FIPS 204 Algorithm 2.
   */
  readonly extraEntropy?: Uint8Array;
}

export interface VerifyOptions {
  /**
   * Optional context string (max 255 bytes) for domain separation per NIST FIPS 204 Section 5.
   * MUST match the context string provided during signing.
   */
  readonly context?: Uint8Array | string;
}

function getNobleInstance(name: MlDsaParameterName) {
  switch (name) {
    case 'ML-DSA-44':
      return ml_dsa44;
    case 'ML-DSA-65':
      return ml_dsa65;
    case 'ML-DSA-87':
      return ml_dsa87;
    default:
      throw new Error(`UNSUPPORTED_ML_DSA_PARAMETER_SET: ${name}`);
  }
}

function normalizeContext(context?: Uint8Array | string): Uint8Array | undefined {
  if (context === undefined) return undefined;
  let ctxBytes: Uint8Array;
  if (typeof context === 'string') {
    ctxBytes = new Uint8Array(Buffer.from(context, 'utf8'));
  } else if (context instanceof Uint8Array) {
    ctxBytes = context;
  } else {
    throw new Error('INVALID_CONTEXT_TYPE: Context must be a string or Uint8Array');
  }

  if (ctxBytes.length > 255) {
    throw new Error(`CONTEXT_TOO_LONG: FIPS 204 context string must be at most 255 bytes (got ${ctxBytes.length})`);
  }
  return ctxBytes;
}

export class MlDsaEngine {
  /**
   * NIST FIPS 204 ML-DSA Key Generation (Algorithm 1)
   * Generates a module-lattice digital signature key pair (pk, sk).
   */
  public generateKeyPair(
    paramName: MlDsaParameterName = ML_DSA_65.name,
    options: KeyGenOptions = {}
  ): Readonly<MlDsaKeyPair> {
    const params = getMlDsaParameters(paramName);
    const noble = getNobleInstance(paramName);

    let seed: Uint8Array | undefined;
    if (options.seed !== undefined) {
      if (!(options.seed instanceof Uint8Array) || options.seed.length !== 32) {
        throw new Error('INVALID_SEED_LENGTH: ML-DSA key generation seed (xi) must be exactly 32 bytes');
      }
      seed = options.seed;
    } else {
      seed = new Uint8Array(randomBytes(32));
    }

    const { publicKey, secretKey } = noble.keygen(seed);

    if (!validatePublicKey(publicKey, params) || !validateSecretKey(secretKey, params)) {
      throw new Error('INTERNAL_KEY_VALIDATION_FAILURE: Generated keys do not match FIPS 204 byte lengths');
    }

    return Object.freeze({
      publicKey: new Uint8Array(publicKey),
      secretKey: new Uint8Array(secretKey),
      parameterSet: paramName
    });
  }

  /**
   * NIST FIPS 204 ML-DSA Signing (Algorithm 2)
   * Signs message M using secret key sk and optional domain separation context string.
   */
  public sign(
    message: Uint8Array,
    secretKey: Uint8Array,
    paramName: MlDsaParameterName = ML_DSA_65.name,
    options: SignOptions = {}
  ): Readonly<MlDsaSignatureResult> {
    const params = getMlDsaParameters(paramName);
    if (!validateSecretKey(secretKey, params)) {
      throw new Error(`INVALID_SECRET_KEY: Secret key length must be ${params.secretKeyBytes} bytes for ${paramName}`);
    }
    if (!(message instanceof Uint8Array)) {
      throw new Error('INVALID_MESSAGE_TYPE: Message must be a Uint8Array');
    }

    const context = normalizeContext(options.context);
    const noble = getNobleInstance(paramName);

    const nobleOpts: { context?: Uint8Array; extraEntropy?: Uint8Array } = {};
    if (context) nobleOpts.context = context;
    if (options.extraEntropy) nobleOpts.extraEntropy = options.extraEntropy;

    const signature = noble.sign(message, secretKey, nobleOpts);

    if (!validateSignature(signature, params)) {
      throw new Error('INTERNAL_SIGNATURE_VALIDATION_FAILURE: Output signature length does not match FIPS 204');
    }

    return Object.freeze({
      signature: new Uint8Array(signature),
      parameterSet: paramName
    });
  }

  /**
   * NIST FIPS 204 ML-DSA Verification (Algorithm 3)
   * Verifies signature sigma on message M using public key pk and context string.
   * Returns true if valid, false if invalid or corrupted.
   */
  public verify(
    signature: Uint8Array,
    message: Uint8Array,
    publicKey: Uint8Array,
    paramName: MlDsaParameterName = ML_DSA_65.name,
    options: VerifyOptions = {}
  ): boolean {
    const params = getMlDsaParameters(paramName);
    if (!validatePublicKey(publicKey, params)) {
      return false;
    }
    if (!validateSignature(signature, params)) {
      return false;
    }
    if (!(message instanceof Uint8Array)) {
      return false;
    }

    try {
      const context = normalizeContext(options.context);
      const noble = getNobleInstance(paramName);
      const nobleOpts: { context?: Uint8Array } = {};
      if (context) nobleOpts.context = context;

      return noble.verify(signature, message, publicKey, nobleOpts);
    } catch {
      return false;
    }
  }
}
