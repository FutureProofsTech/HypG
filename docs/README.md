# HypG documentation

**Status of the implementation described here:** research prototype.
Unaudited. Not production-ready. Not NIST-compliant, certified, or
validated. The lattice hardness of the KEM parameters is not confirmed.
There are no power, electromagnetic, or fault-injection laboratory
results. Do not deploy this code to protect real assets.

This directory is the authoritative documentation set for workspace
version **2.0.0**, including the **2.0.1** revision of the HypG-DS wire
format and specification. The code and the frozen KAT files are the final
arbiters of behaviour; if prose and code disagree, the code and KATs win
and the prose is defective.

## Version map

| Component | Code version | Wire/spec revision | Frozen vectors |
|---|---|---|---|
| Workspace | `2.0.0` | — | — |
| `hypg-core` | `2.0.0` | core v2.0 | shared with users |
| `hypg-kem` | `2.0.0` | KEM v2.0 (`HYP-G/v07/...` domains) | `kats/v2.0.0.txt` |
| `hypg-symm` | `2.0.0` | Symm v2.0 (construction unchanged from v0.7) | `kats-symm/v2.0.0.txt` |
| `hypg-aead` | `2.0.0` | Symm v2.0, byte-identical to one-shot | covered by symm KATs |
| `hypg-hash` | `2.0.0` | Hash v2.0 (BLAKE3 API) | `kats-hash/v2.0.0.txt` |
| `hypg-ds` | `2.0.0` | **DS v2.0.1** | `kats-ds/v2.0.1.txt` |
| `hypg-mt` | `2.0.0` | output identical to DS v2.0.1 | covered by DS KATs |
| `hypg-cli` | `2.0.0` | command-line wrapper | negative tests |
| `hypg-bench`, `hypg-redteam`, `hypg-lattice` | `2.0.0` | evaluation harnesses | no frozen output |

The literal `HYP-G/v07/...` domain strings in the KEM, hash, key
derivation, and DS randomizer are protocol domain separators. They are
**not** a statement that the current parameters are v0.7. They were kept
to preserve the primitive boundary and frozen vectors across the v2.0
parameter change. See [domains.md](domains.md).

## Reading paths

### I want to understand the construction

1. [notation.md](notation.md) — formal notation, encodings, definitions.
2. [design.md](design.md) — architecture and rationale.
3. [spec.md](spec.md) — normative KEM specification.
4. [spec-ds.md](spec-ds.md) — normative signature specification.
5. [spec-symm.md](spec-symm.md) — one-shot AEAD.
6. [spec-aead.md](spec-aead.md) — streaming AEAD.
7. [spec-hash.md](spec-hash.md) — hash/XOF/KDF API.

### I want to check the numbers

1. [parameters.md](parameters.md) — authoritative parameter register and
   size derivations.
2. [metrics.md](metrics.md) — controlled local benchmark and validation
   results.
3. [testplan.md](testplan.md) — test matrix, evidence levels, release
   gates.
4. [lattice-local.md](lattice-local.md) — local lattice sanity lab.
5. [estimator.md](estimator.md) — external hardness-estimation work order.

### I want to assess the security position

1. [threat-model.md](threat-model.md) — assets, adversaries, trust
   boundaries, non-goals.
2. [nist-alignment.md](nist-alignment.md) — what matches NIST profiles
   and what does not.
3. [audit-prep.md](audit-prep.md) — audit scope, evidence pack, and open
   questions.
4. [deployment.md](deployment.md) — why deployment is prohibited and what
   an operational review would require.

### I want the academic treatment

1. [`../papers/whitepaper.pdf`](../papers/whitepaper.pdf) — White Paper:
   design rationale, architecture, security discussion, related work,
   evaluation methodology, threats to validity.
2. [`../papers/yellowpaper.pdf`](../papers/yellowpaper.pdf) — Yellow
   Paper: normative algorithms, formal definitions, wire layouts,
   domain registry, API contracts, and KAT inventory.

The LaTeX sources are [`../papers/whitepaper.tex`](../papers/whitepaper.tex)
and [`../papers/yellowpaper.tex`](../papers/yellowpaper.tex).  The PDFs
are rebuilt with `pdflatex`.  Both papers repeat the non-deployment and
non-certification status; neither is an audit.

### I want to use the API

1. [api.md](api.md) — public API, ownership, error semantics, CLI.
2. [threading.md](threading.md) — threaded DS signing and the `no_std`
   boundary.
3. [simd.md](simd.md) — scalar implementation, codegen, and portability.

## Evidence vocabulary

The documentation uses these labels consistently.

| Label | Meaning |
|---|---|
| **Normative** | Defines bytes, algorithms, or public contracts. |
| **Derived** | Follows algebraically from normative parameters. |
| **Measured** | Produced by a stated command on a stated machine. |
| **Working estimate** | A heuristic calculation, not a proof or measured result. |
| **Unconfirmed** | No independent confirmation is available. |
| **Out of scope** | Explicitly not claimed or not evaluated. |

The validation evidence is graded in [testplan.md](testplan.md). In
summary: deterministic tests and KATs are strong within their scope;
The latest recorded Miri subset covers the KEM, AEAD, and DS bounds
tests but not full DS signing;
there is no external audit, no formal verification, no coverage-guided
fuzzing campaign, no `dudect`-grade timing evaluation, and no
power/EM/fault campaign.

## Documentation conventions

- Byte offsets are zero-based; ranges are half-open.
- `A || B` is byte concatenation.
- Integers are little-endian unless a table says otherwise.
- Security parameters are public; secret-dependent branches and indices
  are avoided by construction, but this is not a side-channel proof.
- "Category-5 dimensions" means parameter dimensions resembling NIST
  Category 5 profiles. It is not a security-level claim.
- "SLH-DSA-256f-shaped" means the hypertree/FORS dimensions resemble
  FIPS 205 SLH-DSA-256f. It is not a FIPS 205 implementation.

## Historical material

The v1.0 commit and v1.0 KAT files remain in the repository as historical
evidence. They are not the active wire format. The active frozen files
are the four listed in the version map above, totalling **234,114 bytes**
with the checksums in [testplan.md](testplan.md#4-frozen-kat-checksums).

## Repository layout

```text
crates/
  hypg-core/     no_std, no-alloc core: BLAKE3, ChaCha20, CA-PRF,
                 polynomial arithmetic, constant-time helpers
  hypg-kem/      no_std Module-LWE KEM
  hypg-symm/     no_std one-shot AEAD and hash/XOF wrappers
  hypg-aead/     no_std streaming AEAD front
  hypg-ds/       no_std stateless hash-based signatures
  hypg-mt/       std threaded DS signer
  hypg-hash/     no_std hash/XOF/KDF API
  hypg-kat/      deterministic KAT generation and frozen-file gates
  hypg-bench/    timing and throughput harness
  hypg-redteam/  deterministic adversarial harness
  hypg-lattice/  local lattice sanity lab
  hypg-cli/      operator CLI (not production tooling)
```

All library crates use `#![forbid(unsafe_code)]` and have no external
dependencies; all dependency edges are workspace path dependencies.
`hypg-mt`, the CLI, and the evaluation harnesses use `std`; the
cryptographic libraries do not.
