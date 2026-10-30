# Threat model and security claims

**Status:** research prototype, v2.0.0 / DS 2.0.1. Unaudited. Not
production-ready. No security certification is claimed.

This document states what the implementation is intended to protect,
against which adversaries, under which assumptions, and where the
argument stops. It is deliberately narrower than a product security
target document.

## 1. Assets

| Asset | Description |
|---|---|
| KEM shared secret | The 32-byte `ss` output. |
| KEM long-term secret | `sk = seed \|\| fake \|\| pk`, especially `seed` and `fake`. |
| KEM message | The 32-byte `coins` value, which is both the FO message and the randomness input. |
| AEAD key | The 32-byte master key and its derived subkeys. |
| AEAD plaintext | The message and any tentative streaming plaintext. |
| AEAD associated data | Authenticated but public metadata. |
| DS master secret | `esk`, plus the derived `prf`. |
| DS public seed/root | Public values; integrity matters for verification. |
| Signature | The 49,992-byte signature and its encoding. |
| Randomness | Key-generation seeds, encapsulation messages, and nonces. |
| Key material copies | Stack temporaries, buffers, and caller-held copies. |

## 2. Adversary model

The intended adversary is computationally bounded and may be classical
or quantum. The model includes:

- **Network adversary:** can read, modify, replay, reorder, truncate, and
  inject ciphertexts, signatures, nonces, and associated data.
- **Chosen-ciphertext adversary:** can submit arbitrary KEM ciphertexts
  to a decapsulation oracle, subject to the standard IND-CCA2 rules.
- **Chosen-message adversary:** can obtain signatures on messages of its
  choice, subject to a signing-volume limit that the implementation does
  not enforce.
- **Malformed-input adversary:** can supply arbitrary byte strings of the
  protocol's fixed lengths, including all-zero and all-`0xFF` values.
- **Quantum adversary:** may run Grover-style search and quantum SVP
  algorithms. No quantum hardware is assumed.
- **Local software adversary:** may attempt to read process memory,
  crash the process, exploit a dependency, or influence the compiler.
  This is partially outside the model; see §4.
- **Fault adversary:** may induce bit flips or transient faults. The
  implementation has no fault-detection or redundancy claim; fault
  attacks are out of scope for the security claim, though some
  fail-closed behaviour is tested.

The adversary is **not** assumed to have:

- a copy of the long-term secrets;
- the ability to break BLAKE3, ChaCha20, or Module-LWE;
- a quantum computer large enough to run Shor's algorithm;
- physical access to a power/EM laboratory in the claimed evidence;
- control over the operating system or hardware.

## 3. Security goals

### 3.1 KEM

**Intended:** IND-CCA2 for the exact construction, with implicit
rejection, at a bit-security level consistent with the parameter profile.
**Status: unconfirmed.** No reduction for the exact FO variant, no
lattice-estimator result, and no external cryptanalysis.

Secondary goals:

- invalid ciphertexts do not produce a distinguishable public error;
- ciphertexts are bound to `pk`, `m`, and the full ciphertext bytes;
- decapsulation is total and does not panic on arbitrary fixed-length
  inputs;
- accepted and rejected paths perform the same algorithmic work.

### 3.2 AEAD

**Intended:** IND-CPA confidentiality and INT-CTXT integrity for
messages within the block-space limit, under unique nonces and secure
ChaCha20/BLAKE3.
**Status: plausible composition, unproven for this exact instantiation.**

Secondary goals:

- one-shot `open` does not release plaintext before tag verification;
- streaming `open` releases only tentative plaintext and zeroizes it on
  failure;
- truncation, reordering, duplication, and bit flips are rejected;
- key and nonce separation is enforced by derivation contexts and MAC
  input.

### 3.3 Signatures

**Intended:** UF-CMA for a bounded number of signatures per key, with a
security level consistent with the 256-bit hash and the SLH-DSA-shaped
parameters.
**Status: unconfirmed.** No proof for the exact composition and no
signing-volume analysis.

Secondary goals:

- stateless signing (no secret state to clone or roll back);
- deterministic, reproducible signatures;
- malformed encodings and nonzero reserved bytes are rejected;
- out-of-range internal indices fail closed;
- verification does not panic on arbitrary signature bytes.

### 3.4 Implementation

**Intended:** memory-safe Rust, no `unsafe`, no external dependencies,
no allocator in the cryptographic libraries, fixed public loop bounds,
best-effort zeroization.

**Not claimed:** formal constant-time execution, compiler-level
constant-time guarantees, or side-channel resistance.

## 4. Trust boundaries

| Boundary | Trusted? | Consequence |
|---|---|---|
| Caller CSPRNG | Trusted | Weak seeds, coins, or nonces break security. |
| Caller key storage | Trusted | The library cannot protect keys at rest. |
| Operating system | Trusted | A compromised OS can read or alter memory. |
| Compiler / LLVM | Trusted | Safe Rust does not guarantee constant-time codegen. |
| Hardware / microarchitecture | Trusted | Cache, branch predictor, power, and EM effects are not modelled. |
| Build and dependency chain | Mostly trusted | Zero external dependencies reduce, but do not eliminate, supply-chain risk. |
| Protocol framing | Caller's responsibility | The library does not provide message boundaries, replay protection, or key confirmation. |
| Nonce uniqueness | Caller's responsibility | AEAD nonce reuse is catastrophic. |
| Signing volume | Caller's responsibility | FORS is few-time; the library enforces no limit. |
| Secret copies | Caller's responsibility | `seed_copy`, `fake_copy`, `public_copy`, and caller buffers can outlive the library's best-effort wipe. |

## 5. Assumptions

The security claims, such as they are, depend on all of the following.

**A1. Module-LWE hardness.** The Module-LWE instance with `n=256`,
`k=4`, `q=4096`, `eta=2` is hard at the intended level. This is not
confirmed. The power-of-two modulus and the compression profile differ
from ML-KEM-1024.

**A2. BLAKE3.** BLAKE3 is collision-resistant, preimage-resistant, and
secure as a PRF/XOF/MAC in the modes used. The portable scalar
implementation computes standard BLAKE3.

**A3. ChaCha20.** IETF ChaCha20 with a 256-bit key and unique 96-bit
nonce is a secure stream cipher for at most `2^32` blocks per
`(key,nonce)`.

**A4. FO-style transform.** The exact re-encryption and implicit-
rejection construction has CCA security under A1–A2. This is a
conjecture, not a theorem in this repository.

**A5. Random oracles.** The hash/XOF/KDF calls used as `G`, `H`, and
`KDF` behave as independent random oracles with the stated domain
separation. The `CA-PRF` does not add an independent assumption; its
final BLAKE3 XOF is the relevant object.

**A6. No decapsulation failures.** The noise plus compression residual
stays inside the decoding region with probability at least `1 - 2^-128`
for all honestly generated keys and ciphertexts. This is a working
estimate (`~14.6 sigma`), not a proven bound.

**A7. Unique nonces.** Every `(key, nonce)` pair is used for at most one
message in the AEAD. The library does not enforce this.

**A8. Bounded signing.** The number of signatures per DS key is within
the range for which the FORS/hypertree security bound is acceptable.
The library does not enforce a limit.

**A9. Secret storage.** The caller protects secret keys and shared
secrets at rest and in memory. The library's zeroization is best-effort
and cannot defeat a memory disclosure.

**A10. Side-channel model.** The implementation is intended to avoid
secret-dependent branches and indices, but no formal constant-time or
physical side-channel claim is made.

## 6. Non-goals

HypG does not attempt to provide:

- a replacement for ML-KEM, ML-DSA, SLH-DSA, or a validated AEAD in a
  production system;
- FIPS 140-3 validation, CMVP certification, ACVP/CAVP validation, or
  NIST compliance;
- nonce-misuse-resistant encryption;
- key commitment;
- forward secrecy by itself (a protocol can combine the KEM with an
  ephemeral key exchange, but the KEM API does not impose one);
- replay protection, message ordering, identity binding, or
  authorization;
- authenticated key exchange, password-based encryption, or key
  derivation from low-entropy secrets;
- protection against a compromised RNG, OS, compiler, or hardware;
- fault detection or redundancy;
- power/EM/timing side-channel resistance;
- secure deletion from physical media;
- long-term key management, rotation, revocation, or HSM integration;
- anonymity or metadata protection;
- a formal security proof.

## 7. Attack-surface review

| Surface | Main risks | Current mitigation | Residual risk |
|---|---|---|---|
| KEM `encaps(pk, coins)` | Coins reuse; biased message; malformed `pk` | Deterministic G binds `m,pk`; total parsing | Caller can reuse coins; no pk validation |
| KEM `decaps` | Invalid ciphertext oracle; timing | Implicit rejection; full re-encryption; `ct_eq`; `ct_select` | No dudect/power evidence; exact FO proof missing |
| AEAD `seal/open` | Nonce reuse; length confusion; tag forgery | EtM; length suffix; 256-bit tag; full-scan compare | No misuse resistance; no composition proof |
| Streaming AEAD | Tentative plaintext released early | Documented rule; zeroize on failure | Caller copies are outside control |
| DS `sign` | FORS/WOTS reuse; deterministic R; stack use | Stateless; full tree builds; zeroization | No signing-volume bound; deterministic privacy loss |
| DS `verify` | Malformed signature; ignored fields; root compare | Exact length; zero pad check; `ct_eq` root | No SUF proof; no timing lab |
| Parsing | Panics or OOB on hostile bytes | Fixed arrays; fail-closed indices; total `dot` | Safe Rust eliminates memory unsafety, not logic bugs |
| CLI | Shell injection; secret leakage in argv | Strict parsing; no shell eval; hex parsing | Secrets passed as command-line arguments are visible to the OS |
| Threading | Data races; nondeterministic output | Scoped threads; owned per-unit outputs; join fallback | Platform thread failure is handled, but no formal scheduler model |
| Build | Supply chain; feature drift | Zero external dependencies; locked workspace; CI | Rust toolchain and OS are trusted |

## 8. Failure semantics

- **KEM:** `decaps` never fails. A forged ciphertext yields a
  pseudorandom `ss`. Protocols must confirm the shared secret through a
  subsequent authenticator.
- **AEAD one-shot:** `open` returns `None` and leaves `pt` untouched on
  failure. Do not interpret `None` as an empty plaintext.
- **AEAD streaming:** `update` may write tentative plaintext; only
  `finish == Some(())` authenticates it. Failure zeroizes the assembled
  buffer.
- **DS:** `ds_verify` returns `false` for any length or encoding error.
  There is no exception path.
- **CLI:** exit code `2` means usage/input error; exit code `3` means
  authentication failure. Exit code `0` includes KEM decapsulation of an
  invalid ciphertext, because that operation returns a secret rather than
  an error.

## 9. Evidence and claims matrix

| Claim | Evidence | Status |
|---|---|---|
| Deterministic KATs match the implementation | Frozen files + tests | Verified locally |
| x86-64 and aarch64 produce identical KAT bytes | Cross-arch run | Verified locally |
| KEM round-trip and implicit rejection on tested inputs | Unit/red-team tests | Verified locally |
| KEM IND-CCA2 | No proof; no estimator | **Not claimed** |
| KEM failure probability ≤ `2^-128` | 32-trial tripwire + heuristic | **Not established** |
| AEAD tamper rejection on tested inputs | Tests/red-team | Verified locally |
| AEAD IND-CPA/INT-CTXT | Composition argument only | **Not proven** |
| DS sign/verify and tamper rejection | Tests/KATs | Verified locally |
| DS UF-CMA/SUF-CMA | No proof; no review | **Not claimed** |
| Memory safety in safe Rust | `forbid(unsafe_code)`, Miri subsets | Partially verified |
| Constant-time execution | Branchless source patterns | **Not verified** |
| Power/EM/fault resistance | None | **Not evaluated** |
| NIST/FIPS compliance | None | **Not claimed** |

## 10. Reporting and review

This is a research repository, not a bug-bounty program. Security-
relevant findings should include:

- the exact commit hash;
- the target triple and toolchain;
- a minimal reproducer;
- the observed and expected behaviour;
- whether the issue affects a frozen invariant (determinism, failure
  rate, panic on valid input, memory safety, domain separation).

See [SECURITY.md](../SECURITY.md) for the reporting posture. Do not
represent a local test pass as an audit or a production readiness
statement.
