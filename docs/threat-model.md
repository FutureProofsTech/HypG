# HypG Threat Model (frozen for v1.0; parameters v0.7/v0.6)

## Goals

- IND-CCA2 KEM at Kyber-512-class hardness (Module-LWE `n = 256`,
  `k = 2`, dim 512, `q = 2^12`, `eta = 2`), branchless deterministic
  `no_std` execution, `pk = ct = 800 B`.
- BLAKE3 hashing/XOF/KDF used as designed (oracle-validated, no custom
  symmetric modes); ChaCha20 + keyed-BLAKE3 EtM AEAD (one-shot and
  streaming, wire-identical); SLH-shaped hash-based signatures.
- The original `<256 B` target is **retired**: incompatible with 128-bit
  PQ at current knowledge (all NIST finalists exceed it).

## What changed in v0.3

- Scaled v0.2's toy ring (`n = 64`) to module rank 2 over `X^256+1`.
  Message encoding relaxed from 4 bits/coeff to 1 bit/coeff (spacing
  2048, threshold 1024) — far larger noise margin, negligible failure.
- `c2` compression `12→5` bits (160 B), `c1` stays `12→10` (320 B/poly).
- Power-of-two `q = 4096` retained instead of Kyber's `3329` for
  branchless mask-only reduction (no division); documented deviation.

## Attacker capabilities assumed

- Quantum: Grover + quantum-sieve BKZ cost models.
- Classical: CPA/CCA oracles, timing + cache observation.
- Supply-chain: zero deps to compromise.

## Explicit non-goals / disclaimers (frozen for v1.0)

1. **No confirmed bit-security.** Kyber-class dimensions suggest
   `~100+`-bit classical hardness, but the lattice-estimator run and
   independent parameter review are still backlog. Do not deploy.
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

- Deploying v1.0 in production. → crate docs + SECURITY.md warnings.
- Shrinking `(n, k)` or `eta` to regain `<256 B`. → spec forbids; CI pins KATs.
- Adding deps/`unsafe` (e.g. fast NTT). → CI denies; NTT stays naive `O(n²)`.
- Inventing symmetric modes (sponge, truncated tags). → README non-goals; CI pins KATs.

## 1.0 sign-off (2026-09-29, local review)

- Abuse cases above re-checked: warnings present (README, SECURITY.md,
  all spec statuses `FROZEN`, crate docs); KAT pinning green (4 frozen
  files); hygiene gates deny deps/`unsafe`/`panic!`/`unwrap`.
- Residual risks accepted as documented, not resolved: unconfirmed
  bit-security (`estimator.md`), no lab side-channels, no human audit.
  The freeze certifies *process completeness* (everything on the local
  matrix is done), not security.
