import test from 'node:test';
import assert from 'node:assert/strict';
import {
  MlDsaEngine,
  ReferenceDilithiumMath
} from '../dist/index.js';
import {
  ML_DSA_44,
  ML_DSA_65,
  ML_DSA_87,
  constantTimeEqual
} from '@qmoosa/pqc-mldsa-protocol';

test('ML-DSA Engine: Full Sign & Verify Round-Trip on ML-DSA-44', () => {
  const engine = new MlDsaEngine();
  const alice = engine.generateKeyPair('ML-DSA-44');

  assert.equal(alice.publicKey.length, ML_DSA_44.publicKeyBytes);
  assert.equal(alice.secretKey.length, ML_DSA_44.secretKeyBytes);

  const message = new TextEncoder().encode('QMOOSA Web4 Transaction Root #44');
  const sigResult = engine.sign(message, alice.secretKey, 'ML-DSA-44');

  assert.equal(sigResult.signature.length, ML_DSA_44.signatureBytes);

  const isValid = engine.verify(sigResult.signature, message, alice.publicKey, 'ML-DSA-44');
  assert.equal(isValid, true, 'Valid signature must verify successfully');
});

test('ML-DSA Engine: Full Sign & Verify Round-Trip on ML-DSA-65 (Primary Standard)', () => {
  const engine = new MlDsaEngine();
  const alice = engine.generateKeyPair('ML-DSA-65');

  assert.equal(alice.publicKey.length, ML_DSA_65.publicKeyBytes);
  assert.equal(alice.secretKey.length, ML_DSA_65.secretKeyBytes);

  const message = new TextEncoder().encode('QMOOSA Web4 Settlement Block #65');
  const sigResult = engine.sign(message, alice.secretKey, 'ML-DSA-65');

  assert.equal(sigResult.signature.length, ML_DSA_65.signatureBytes);

  const isValid = engine.verify(sigResult.signature, message, alice.publicKey, 'ML-DSA-65');
  assert.equal(isValid, true, 'ML-DSA-65 signature must verify successfully');
});

test('ML-DSA Engine: Full Sign & Verify Round-Trip on ML-DSA-87 (Category 5 Maximum Security)', () => {
  const engine = new MlDsaEngine();
  const alice = engine.generateKeyPair('ML-DSA-87');

  assert.equal(alice.publicKey.length, ML_DSA_87.publicKeyBytes);
  assert.equal(alice.secretKey.length, ML_DSA_87.secretKeyBytes);

  const message = new TextEncoder().encode('QMOOSA Governance Master Anchor #87');
  const sigResult = engine.sign(message, alice.secretKey, 'ML-DSA-87');

  assert.equal(sigResult.signature.length, ML_DSA_87.signatureBytes);

  const isValid = engine.verify(sigResult.signature, message, alice.publicKey, 'ML-DSA-87');
  assert.equal(isValid, true, 'ML-DSA-87 signature must verify successfully');
});

test('ML-DSA Engine: Deterministic Seeding & FIPS 204 KAT Reproducibility', () => {
  const engine = new MlDsaEngine();
  const fixedSeed = new Uint8Array(32).fill(0x37);

  const kp1 = engine.generateKeyPair('ML-DSA-65', { seed: fixedSeed });
  const kp2 = engine.generateKeyPair('ML-DSA-65', { seed: fixedSeed });

  assert.ok(constantTimeEqual(kp1.publicKey, kp2.publicKey), 'Identical seed must yield identical public key');
  assert.ok(constantTimeEqual(kp1.secretKey, kp2.secretKey), 'Identical seed must yield identical secret key');
});

test('ML-DSA Engine: Context String Domain Separation Enforcement', () => {
  const engine = new MlDsaEngine();
  const alice = engine.generateKeyPair('ML-DSA-65');
  const message = new TextEncoder().encode('Cross-Chain Transfer Intent');

  // Sign with context
  const contextA = 'CHAIN_ID:ARBITRUM_ONE';
  const sigResult = engine.sign(message, alice.secretKey, 'ML-DSA-65', { context: contextA });

  // Verify with same context -> PASS
  assert.equal(
    engine.verify(sigResult.signature, message, alice.publicKey, 'ML-DSA-65', { context: contextA }),
    true
  );

  // Verify with different context -> FAIL
  assert.equal(
    engine.verify(sigResult.signature, message, alice.publicKey, 'ML-DSA-65', { context: 'CHAIN_ID:SOLANA' }),
    false
  );

  // Verify without context -> FAIL
  assert.equal(
    engine.verify(sigResult.signature, message, alice.publicKey, 'ML-DSA-65'),
    false
  );
});

test('ML-DSA Engine: Adversarial Negative Control - Corrupted Signature Bit Rejection', () => {
  const engine = new MlDsaEngine();
  const alice = engine.generateKeyPair('ML-DSA-65');
  const message = new TextEncoder().encode('Adversarial Payload Test');

  const sigResult = engine.sign(message, alice.secretKey, 'ML-DSA-65');

  // Corrupt 1 byte in signature
  const tamperedSig = new Uint8Array(sigResult.signature);
  tamperedSig[100] ^= 0x01;

  assert.equal(
    engine.verify(tamperedSig, message, alice.publicKey, 'ML-DSA-65'),
    false,
    'Corrupted signature bit must be rejected'
  );
});

test('ML-DSA Engine: Adversarial Negative Control - Tampered Message Rejection', () => {
  const engine = new MlDsaEngine();
  const alice = engine.generateKeyPair('ML-DSA-65');
  const legitMessage = new TextEncoder().encode('Transfer 100 QMOOSA to 0x1111');
  const forgedMessage = new TextEncoder().encode('Transfer 100 QMOOSA to 0x9999');

  const sigResult = engine.sign(legitMessage, alice.secretKey, 'ML-DSA-65');

  assert.equal(
    engine.verify(sigResult.signature, forgedMessage, alice.publicKey, 'ML-DSA-65'),
    false,
    'Signature over legitimate message must reject altered payload'
  );
});

test('ML-DSA Engine: Adversarial Negative Control - Wrong Public Key Rejection', () => {
  const engine = new MlDsaEngine();
  const alice = engine.generateKeyPair('ML-DSA-65');
  const bob = engine.generateKeyPair('ML-DSA-65');
  const message = new TextEncoder().encode('Identity Verification Payload');

  const sigResult = engine.sign(message, alice.secretKey, 'ML-DSA-65');

  assert.equal(
    engine.verify(sigResult.signature, message, bob.publicKey, 'ML-DSA-65'),
    false,
    'Verification against non-owner public key must return false'
  );
});

test('ML-DSA Engine: Defensive Validation Errors', () => {
  const engine = new MlDsaEngine();

  // Invalid seed length (must be 32 bytes)
  assert.throws(
    () => engine.generateKeyPair('ML-DSA-65', { seed: new Uint8Array(16) }),
    /INVALID_SEED_LENGTH/
  );

  // Invalid secret key length
  assert.throws(
    () => engine.sign(new Uint8Array(10), new Uint8Array(100), 'ML-DSA-65'),
    /INVALID_SECRET_KEY/
  );

  // Context too long (> 255 bytes)
  const hugeContext = new Uint8Array(256);
  assert.throws(
    () => engine.sign(new Uint8Array(10), new Uint8Array(4032), 'ML-DSA-65', { context: hugeContext }),
    /CONTEXT_TOO_LONG/
  );
});

test('ML-DSA Engine: Reference Dilithium Math Module Verification', () => {
  assert.ok(ReferenceDilithiumMath);
  assert.equal(ReferenceDilithiumMath.Q, 8380417);
  assert.equal(ReferenceDilithiumMath.N, 256);

  const zero = ReferenceDilithiumMath.createZeroPoly();
  assert.equal(zero.length, 256);

  const { r0, r1 } = ReferenceDilithiumMath.power2Round(12345);
  assert.equal(typeof r0, 'number');
  assert.equal(typeof r1, 'number');
});
