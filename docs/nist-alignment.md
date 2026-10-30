# NIST alignment and production-gap analysis

**Status:** gap analysis, not a compliance claim. HypG v2.0 is not
NIST-compliant, not FIPS-validated, not certified, and not a substitute
for ML-KEM, ML-DSA, or SLH-DSA.

## 1. What "Category-5 dimensions" means here

NIST's security categories are defined in terms of the resources needed
to break a scheme, not in terms of a tuple of ring dimensions. HypG uses
parameters whose dimensions resemble NIST Category-5 profiles:

- KEM: `n = 256`, module rank `k = 4`, lattice dimension 1024, modulus
  `q = 4096`, `CBD(2)`.
- Signatures: `n = 32`, total height 68, 17 layers of height 4, FORS
  `(k=35,a=9)`, WOTS+ `w=16`.

The word "dimensions" is deliberate. No bit-security level is claimed,
and no NIST category is certified.

## 2. KEM comparison

| Property | ML-KEM-1024 (FIPS 203) | HypG KEM v2.0 |
|---|---|---|
| Ring | `Z_3329[X]/(X^256+1)` | `Z_4096[X]/(X^256+1)` |
| Module rank | 4 | 4 |
| Lattice dimension | 1024 | 1024 |
| Secret/error | `eta1=2`, `eta2=2` | `CBD(2)` for all |
| Public key | 1568 B | 1568 B |
| Ciphertext | 1568 B | **1440 B** |
| Secret key | 3168 B | **1632 B** |
| Shared secret | 32 B | 32 B |
| Compression | `du=11`, `dv=5` bits | `c1=10`, `c2=5` bits |
| Transform | ML-KEM FO with implicit rejection | FO-style with implicit rejection |
| Hash primitives | SHA-3/SHAKE | BLAKE3 |
| NIST status | Standard | **Not standard, not validated** |

The equal public-key size is a coincidence of the parameter choices, not
an interoperability property. The ciphertexts are not compatible. The
secret-key layout differs. HypG uses a power-of-two modulus to avoid
division and Barrett reduction; this changes the lattice profile.
ML-KEM-1024 hardness estimates cannot be transferred to `q = 4096`
without a fresh estimator run.

HypG also compresses `c1` to 10 bits rather than ML-KEM-1024's 11. The
correctness analysis in [spec.md](spec.md#6-correctness) accounts for
the compression residual heuristically; it is not an ML-KEM correctness
proof.

## 3. Signature comparison

| Property | SLH-DSA-256f (FIPS 205) | HypG-DS v2.0.1 |
|---|---|---|
| Hash output | 256 bits | 256 bits |
| Total height | 68 | 68 |
| Layers | 17 | 17 |
| Layer height | 4 | 4 |
| FORS | `k=35`, `a=9` | `k=35`, `a=9` |
| WOTS+ | `w=16`, `len=67` | `w=16`, `len=67` |
| Public key | 64 B | 64 B |
| Secret key | 128 B | 128 B |
| Signature | 49,856 B | **49,992 B** |
| Hash function | SHA-2 or SHAKE | BLAKE3 |
| Address layout | FIPS 205 ADRS | 32-byte custom ADRS |
| Randomizer | Hedged/randomized option | Deterministic only |
| Reserved bytes | None | 8 B per layer |
| NIST status | Standard | **Not standard, not validated** |

The 136-byte difference is exactly `17 × 8` reserved bytes. Those bytes
must be zero; verification rejects any nonzero value. They are an
encoding discipline, not a NIST feature.

HypG-DS is **SLH-DSA-256f-shaped**, not SLH-DSA. The tweakable hash is
keyed BLAKE3 with explicit `PRF`/`F` tags; FIPS 205 uses SHA-2/SHAKE
constructions and its own address semantics. The deterministic
randomizer means repeated signing of the same message is byte-identical.
No signing-volume analysis is included, and FORS is few-time.

## 4. AEAD comparison

There is no NIST-standard "ChaCha20 + keyed BLAKE3 EtM" AEAD. The
construction is structurally standard Encrypt-then-MAC, but:

- ChaCha20 is not a FIPS-approved block/stream cipher for FIPS 140
  modules.
- BLAKE3 is not a FIPS-approved hash or MAC.
- The composition has not been standardized by NIST.
- There is no nonce-misuse resistance.

It would be inaccurate to describe it as "AES-GCM-like" or
"ChaCha20-Poly1305-compatible". It is a separate construction with a
different tag function and key schedule.

## 5. Hash and RNG comparison

| Function | NIST-approved option | HypG |
|---|---|---|
| Hash | SHA-256/SHA-3 | BLAKE3 |
| XOF | SHAKE128/256 | BLAKE3 XOF |
| MAC | HMAC, KMAC, GMAC | keyed BLAKE3 |
| KDF | HKDF, KBKDF | BLAKE3 derive_key / XOF |
| AEAD | AES-GCM (approved); ChaCha20-Poly1305 is not generally FIPS-approved | ChaCha20 + keyed BLAKE3 |
| RNG | SP 800-90A/B/C DRBG | caller-supplied CSPRNG, no DRBG |

The library does not implement a NIST DRBG. It consumes caller-supplied
seeds and coins. The CLI reads `/dev/urandom`; that is an OS facility,
not a NIST-validated DRBG.

## 6. What is genuinely NIST-shaped

The following are dimensionally or structurally similar:

- Module-LWE KEM with rank 4 over `X^256+1`, `CBD(2)`, and a 32-byte
  message encoded one bit per coefficient.
- FO-style re-encryption with implicit rejection and a 32-byte shared
  secret.
- Hypertree/FORS/WOTS+ signature dimensions matching SLH-DSA-256f.
- Encrypt-then-MAC with a 256-bit tag and a 96-bit nonce.
- 256-bit hash outputs and arbitrary-length XOFs.

These similarities are useful for readers familiar with the NIST
standards. They are not evidence of compliance or of equivalent
security.

## 7. What blocks a compliance or production claim

1. **Unapproved primitives.** BLAKE3 and ChaCha20 are not FIPS-approved
   for the relevant roles. A FIPS-targeted variant would need SHA-3/SHAKE
   and an approved AEAD, which is a new protocol, not a build flag.
2. **No validation.** There is no ACVP/CAVP test campaign, no CMVP
   certificate, no FIPS 140-3 module boundary, and no NIST submission.
3. **No estimator result.** The Module-LWE hardness of the exact
   `(n=256,k=4,q=4096,eta=2)` parameters is unconfirmed. The modulus
   deviation is exactly why ML-KEM numbers cannot be reused.
4. **No signature proof.** The exact FORS/WOTS+/XMSS composition,
   BLAKE3-based tweakable hash, deterministic randomizer, and reserved
   bytes have not been reduced to a published theorem or independently
   reviewed. FORS few-time security and signing volume are not analysed.
5. **No side-channel evidence.** Branchless source patterns are not a
   `dudect` result, and there is no power/EM/fault campaign.
6. **No implementation assurance.** There is no third-party code audit,
   no formal verification, and no coverage-guided fuzzing campaign.
7. **Operational gaps.** Key storage, RNG, nonce management, protocol
   framing, replay protection, and secure deletion are caller
   responsibilities. The libraries provide no OS integration.

## 8. Honest positioning

A defensible one-sentence description is:

> HypG v2.0 is a zero-external-dependency, safe-Rust research
> implementation whose KEM and signature dimensions resemble NIST
> Category-5 profiles, with reproducible local tests, KATs, benchmarks,
> and an explicit, documented gap to any production or compliance
> claim.

It is not "better than NIST standards", not a drop-in replacement for
ML-KEM/ML-DSA/SLH-DSA, and not a validated cryptographic module. Its
value is transparency: the parameters, vectors, benchmarks, adversarial
tests, and residual risks are in the repository and reproducible.

## 9. Path to a defensible production profile

If the goal is a deployable system, the shortest honest path is:

1. Run the community lattice-estimator on the exact `q=4096`, `k=4`
   parameters and publish classical and quantum cost tables.
2. Obtain independent review of the FO variant, the DS composition and
   signing-volume bound, and the role of `CA-PRF`.
3. Bound the decapsulation failure probability analytically and measure
   it at `>= 10^6` trials.
4. Complete timing, power/EM, and fault-injection evaluation.
5. Add coverage-guided fuzzing and a protocol-level misuse analysis.
6. If FIPS compliance is required, redesign around approved primitives
   and pursue ACVP/CAVP and CMVP validation.
7. Commission a third-party audit before any production claim.

Until then, HypG should remain in test systems and research evaluation,
with the version pinned explicitly and the non-claims repeated wherever
results are cited.
