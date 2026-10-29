# HypG Threat Model (frozen for v2.0; parameters v2.0)

## Goals

- IND-CCA2 KEM at NIST Category-5 *dimensions* (Module-LWE `n = 256`,
  `k = 4`, dim 1024, `q = 2^12`, `eta = 2`), branchless deterministic
  `no_std` execution, `pk = 1568 B`, `ct = 1440 B`.
- BLAKE3 hashing/XOF/KDF used as designed (oracle-validated, no custom
  symmetric modes); ChaCha20 + keyed-BLAKE3 EtM AEAD (one-shot and
  streaming, wire-identical); SLH-DSA-256f-shaped hash-based signatures
  (`h = 68`, `d = 17`, FORS `35×9`).
- The original `<256 B` target is **retired**: incompatible with 128-bit
  PQ at current knowledge (all NIST finalists exceed it).

## What changed in v2.0

- Module rank raised from `k = 2` to `k = 4` (lattice dimension 512 →
  1024). `pk`/`ct` grow to 1568/1440 B; this is a breaking wire-format
  change.
- Signature profile raised to the SLH-DSA-256f shape: `h = 68`, `d = 17`,
  `h' = 4`, FORS `(35,9)`, `sig = 49992 B`.
- Power-of-two `q = 4096` retained instead of Kyber's `3329` for
  branchless mask-only reduction (no division); documented deviation.
- v1.0 parameters and KAT files remain in the tree as historical
  evidence; the active KAT set is `kats*/v2.0.0.txt`.

## Attacker capabilities assumed

- Quantum: Grover + quantum-sieve BKZ cost models.
- Classical: CPA/CCA oracles, timing + cache observation.
- Supply-chain: zero deps to compromise.

## Explicit non-goals / disclaimers (frozen for v2.0)

1. **No confirmed bit-security.** Category-5 dimensions put the KEM in
   the Kyber-1024 neighbourhood, but the larger `q` changes the lattice
   profile and the estimator run and independent parameter review are
   still backlog. Do not deploy.
2. **No undecidability-based security.** As in all versions: bounded CA
   is decidable; security is argued from Module-LWE + ROM only.
3. **No side-channel immunity.** Branchless timing posture only; no
   power/EM/fault claims.
4. **Heuristic `CA-PRF`.** Outer BLAKE3 preserves ROM uniformity; CA
   mixing is an unreduced hedge.
5. **No custom symmetric designs.** Sponge/permutation proposals are
   rejected (see README non-goals); BLAKE3/`ChaCha20` as designed.

## Trust boundaries

- Caller supplies `seed`/`coins` from a real CSPRNG; lib has no RNG.
- `sk` handling (zeroize, mlock) is caller responsibility.
- KATs pin behavior, not security.

## Abuse cases to block before release

- Deploying v2.0 in production. → crate docs + SECURITY.md warnings.
- Shrinking `(n, k)` or `eta` to regain `<256 B`. → spec forbids; CI pins KATs.
- Adding deps/`unsafe` (e.g. fast NTT). → CI denies; NTT stays naive `O(n²)`.
- Inventing symmetric modes (sponge, truncated tags). → README non-goals; CI pins KATs.

## 2.0 sign-off (2026-10-30, local review)

- Abuse cases above re-checked: warnings present (README, SECURITY.md,
  all spec statuses `FROZEN`, crate docs); KAT pinning green (4 frozen
  v2.0.0 files); hygiene gates deny deps/`unsafe`/`panic!`/`unwrap`.
- Residual risks accepted as documented, not resolved: unconfirmed
  bit-security (`estimator.md`), no lab side-channels, no human audit.
  The freeze certifies *process completeness* (everything on the local
  matrix is done), not security.
