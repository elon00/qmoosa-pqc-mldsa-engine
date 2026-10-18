# @qmoosa/pqc-mldsa-engine

**QMOOSA Post-Quantum Cryptography — NIST FIPS 204 ML-DSA Audited Signature Engine & Invariant Verification**

Part of the **QMOOSA-1000 Sovereign Web4 Infrastructure Portfolio** (Repository 057 / 1,000, Domain 2: Post-Quantum Cryptography & Zero-Knowledge Reality Gates, Batch 12).

---

## 1. Architecture & Audited Cryptographic Primitives

`@qmoosa/pqc-mldsa-engine` delivers production-grade module-lattice post-quantum digital signature operations conforming strictly to **NIST FIPS 204**.

- **Cryptographic Provider:** Production key generation, signing, and verification are delegated directly to the audited, verified implementation in `@noble/post-quantum/ml-dsa.js`.
- **Educational Reference Module:** Uncompiled polynomial ring arithmetic ($R_q = \mathbb{Z}_q[X]/(X^{256} + 1)$ with $q = 8380417$) is preserved in `src/reference-dilithium-math.ts` labeled:
  `EDUCATIONAL & ALGORITHMIC REFERENCE ONLY — NOT FOR PRODUCTION SIGNING TRAFFIC`.
- **Domain Separation:** Full native support for FIPS 204 Section 5 context strings (up to 255 bytes) for replay protection across distinct chains and protocols.
- **Deterministic KeyGen:** Reproducible keypair derivation from 32-byte seeds ($\xi$) per FIPS 204 Algorithm 1.

---

## 2. Invariants & Reality Gates

1. **Exact Signature & Key Invariants:** Validates all byte lengths before and after noble execution.
2. **Adversarial Negative Controls:** Verified rejection of 1-bit corrupted signatures, forged messages, mismatched contexts, and non-owner public keys.
3. **Execution Runtime Notice:** Operates on standard V8 Node.js engines. Does not claim FIPS 140-3 laboratory certification or hardware-level constant-time execution.

---

## 3. Scorecard & Status

- **License:** MIT
- **Production Certification Status:** 0 / 1,000 (Locked from mainnet deployment until formal audit sign-offs).
- **Cost Incurred:** $0.00
