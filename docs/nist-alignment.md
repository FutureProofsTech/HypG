# NIST alignment and production-gap analysis (HypG v2.0)

This page maps HypG v2.0 to the NIST post-quantum standards and states,
without rounding up, what matches and what does not. It is a gap
analysis, not a compliance claim.

## 1. Parameter alignment

| NIST reference | NIST parameters | HypG v2.0 | Status |
|---|---|---|---|
| FIPS 205 SLH-DSA-256f | `n=32`, `h=68`, `d=17`, `h'=4`, FORS `(k=35,a=9)`, `w=16` | same shape | **dimensions match** |
| FIPS 203 ML-KEM-1024 | `n=256`, `k=4`, `q=3329`, `eta=2` | `n=256`, `k=4`, `q=4096`, `eta=2` | **dimensions match; modulus/compression differ** |
| FIPS 204 ML-DSA | Module-LWE/SIS signatures | not used | no mapping |
| FIPS 202 SHA-3/SHAKE | Keccak family | BLAKE3 | **not FIPS-approved** |
| SP 800-90A/B/C RNG | approved DRBG | caller-supplied CSPRNG | out of scope |

The KEM's `q = 4096` is deliberate: it permits branchless mask-only
reduction. It also changes the lattice profile relative to ML-KEM's
`3329`, so ML-KEM-1024 hardness numbers cannot be copied across. HypG
also compresses `c1` to 10 bits (ML-KEM-1024 uses 11), so the wire sizes
are not identical either. The lattice estimator must be run on HypG's
exact parameters.

The signature is 49992 B versus FIPS 205's 49856 B: the 136-byte
difference is the 8-byte reserved index pad per layer (17 × 8), kept so
verification can reject nonzero padding explicitly.

## 2. What is genuinely NIST-shaped

- **KEM dimensions**: module rank 4 over `X^256+1`, `eta=2`, 1
  bit/coefficient message encoding, FO with implicit rejection.
- **Signature dimensions**: 256-bit hash, 68-bit hypertree, 17 layers
  of height 4, FORS `35×9`, WOTS+ `w=16`, 49992-byte signature
  (49856 B of FIPS 205-shaped content plus 17 × 8 B reserved pads).
- **AEAD construction**: Encrypt-then-MAC with a 256-bit tag and a
  96-bit nonce; the composition is standard, though the primitives are
  not FIPS-approved.
- **Hash output sizes**: 256-bit digests, arbitrary-length XOF.

## 3. What blocks a NIST-compliance or production claim

1. **Approved algorithms.** FIPS 140-3 / federal use requires
   FIPS-approved primitives. BLAKE3 and ChaCha20 are not FIPS-approved;
   a NIST-compliant variant would need SHA-3/SHAKE and AES/GCM or
   another approved AEAD. HypG deliberately chose portable, widely
   analyzed public primitives instead, and does not claim equivalence.
2. **Validation.** There is no ACVP/CAVP validation, no CMVP
   certificate, and no NIST submission. Parameter dimensions are not a
   certificate.
3. **Estimator.** The Module-LWE hardness of `(n=256, k=4, q=4096,
   eta=2)` has not been confirmed with the lattice-estimator. The
   `q` deviation from ML-KEM is exactly why this cannot be assumed.
4. **Signature analysis.** The FORS/WOTS+/XMSS composition bound for
   HypG's exact `(h,d,k,a,w)` and its BLAKE3-based tweakable hash has
   not been independently reviewed.
5. **Side channels.** The code is branchless by construction, but no
   power/EM/fault laboratory campaign exists. `dudect`-grade timing
   work is also backlog.
6. **Implementation assurance.** No third-party code audit, no formal
   verification, no fuzzing campaign beyond the deterministic
   `hypg-redteam` harness.
7. **Operational controls.** Key storage, RNG, nonce management, and
   zeroization remain caller responsibilities; the libraries are
   `no_std` and provide no OS integration.

## 4. Honest positioning

HypG v2.0 is best described as:

> a zero-dependency, safe-Rust research implementation whose KEM and
> signature *dimensions* match NIST Category-5 profiles, with a
> measured local assurance story and an explicit, documented gap to
> any production or compliance claim.

It is **not** "better than NIST standards", **not** production-ready,
and **not** a substitute for ML-KEM, ML-DSA, SLH-DSA, or a validated
cryptographic module. The value is engineering transparency: the
parameters, vectors, benchmarks, failure sweeps, and remaining risks
are all in the repository and reproducible.

## 5. Path to a defensible production profile

If the goal is a deployable system rather than a research profile, the
shortest honest path is:

1. Run the lattice estimator on the exact `q=4096`, `k=4` parameters
   and publish the classical/quantum cost tables.
2. Obtain independent review of the DS composition and the `CA-PRF`
   construction.
3. Replace BLAKE3/ChaCha20 with FIPS-approved primitives if FIPS
   compliance is required (this is a new protocol version, not a flag).
4. Complete timing, power/EM, and fault-injection evaluation.
5. Commission a third-party audit and an ACVP/CAVP validation effort
   if standardization is the target.

Until then, keep HypG in test systems and pin the version explicitly.
