# HypG — post-quantum cryptographic research suite

**Status: v2.0.0 research prototype; DS wire revision 2.0.1. Unaudited.
Not production-ready. Not NIST-compliant or certified. Do not use it to
protect real keys, messages, or transactions.** The lattice hardness of
the KEM parameters is unconfirmed. There are no power, electromagnetic,
or fault-injection laboratory results.

HypG is a zero-external-dependency, safe-Rust research implementation of a
Module-LWE key-encapsulation mechanism, BLAKE3-based hashing, a
ChaCha20 + keyed-BLAKE3 authenticated encryption scheme (one-shot and
streaming), and stateless hash-based signatures. It includes
deterministic KATs, an adversarial harness, a local lattice lab, and a
gated CI pipeline.

## Highlights

- **Four pillars, one core.** KEM, hash/XOF/KDF, AEAD, and signatures
  share `hypg-core`: portable BLAKE3, ChaCha20, the CA-PRF expander,
  Module-LWE arithmetic, and constant-time helpers.
- **Zero external dependencies, zero `unsafe`.** Every library crate
  uses `#![forbid(unsafe_code)]`; all dependency edges are workspace
  path dependencies, and `cargo tree` contains only workspace crates.
  The cryptographic libraries are `no_std` and do not allocate.
- **Bit-exact determinism.** Frozen KATs are compared byte-for-byte
  across debug/release and x86-64 / `qemu-aarch64`; 234,114 bytes are
  identical.
- **Measured, not assumed.** The release benchmark and all validation
  commands are recorded in [`docs/metrics.md`](docs/metrics.md) and
  [`docs/testplan.md`](docs/testplan.md).
- **Adversarial testing.** 14 red-team suites cover malleability,
  implicit rejection, key mismatch, forgery, malformed inputs, panic
  freedom, and streaming AEAD. The latest records include a
  20,000-trial failure sweep and all 11,520 bit positions of a test
  ciphertext.

## Architecture

```text
hypg-core ──┬── hypg-kem ───────── KEM (keygen/encaps/decaps)
            ├── hypg-hash ──────── hash/XOF/keyed/KDF API
            ├── hypg-symm ──┬───── one-shot AEAD (seal/open)
            │              └───── hypg-aead ── streaming AEAD
            └── hypg-ds ───┬────── signatures (ds_keygen/sign/verify)
                           └────── hypg-mt ─── threaded signer

harnesses: hypg-kat · hypg-bench · hypg-redteam · hypg-lattice · hypg-cli
```

| Pillar | Construction | Sizes |
|---|---|---|
| KEM | Module-LWE (`n=256`, `k=4`, `q=2^12`, dimension 1024), FO-style transform, implicit rejection | `pk` 1568 B, `ct` 1440 B, `sk` 1632 B, `ss` 32 B |
| Hash | Portable BLAKE3 hash/XOF/keyed/derive-key | 32/64 B digests, arbitrary XOF |
| AEAD | ChaCha20 + keyed-BLAKE3 Encrypt-then-MAC, 32 B tag | key 32 B, nonce 12 B, `MAX_MSG_LEN = 2^38` B |
| Signatures | SLH-DSA-256f-shaped FORS `35×9` + 17-layer XMSS hypertree | `pk` 64 B, `sk` 128 B, `sig` 49,992 B |

`HYP-G/v07/...` domain strings are frozen protocol separators; they do
not mean the active parameters are v0.7. The active KEM/Symm/Hash wire
revision is 2.0.0. The DS wire revision is **2.0.1** (PRF/F domain tags
and FIPS-style odd-node promotion). See
[`docs/README.md`](docs/README.md) for the version map.

## Quick start

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace --locked              # 146 tests
cargo test --workspace --locked --release    # 146 tests
cargo +1.70 test --workspace --locked        # MSRV 1.70
cargo run -p hypg-kat                        # frozen-vector check
cargo run -p hypg-redteam                    # S1–S14
cargo run -p hypg-lattice                    # local lattice lab
HYPG_BENCH_ITERS=8 cargo run -p hypg-bench
```

CLI usage (test systems only; see
[`docs/deployment.md`](docs/deployment.md)):

```bash
cargo build --release -p hypg-cli
hypg-cli keygen [--seed HEX64]
hypg-cli encaps <pk_hex> [--coins HEX64]
hypg-cli decaps <sk_hex> <ct_hex>
hypg-cli seal <key64> <nonce24> <ad_hex> <pt_hex>
hypg-cli open <key64> <nonce24> <ad_hex> <ct_hex> <tag64>
hypg-cli hash <hex>
hypg-cli ds-keygen [--esk HEX64]
hypg-cli ds-sign <sk_hex> <msg_hex>
hypg-cli ds-verify <pk_hex> <msg_hex> <sig_hex>
```

Exit codes: `0` success (KEM decapsulation never fails; invalid
ciphertexts yield a pseudorandom secret), `2` usage/input error, `3`
authentication failure. Secrets passed on the command line may be
visible to the OS and shell history.

## Validation record

Recorded on commit `c14169e` with `rustc 1.97.1`:

| Gate | Result |
|---|---|
| Debug / release / MSRV tests | **146/146** each |
| Red-team S1–S14, defaults | **14/14 suites** |
| Failure sweep, release, 20,000 trials | **20,000/20,000** clean |
| Full ciphertext-bit flip sweep (one test ct) | **11,520/11,520** change `ss` |
| Lattice lab | **5/5** checks |
| KAT cross-architecture | **234,114 bytes identical** on x86-64 / `qemu-aarch64` |
| Miri, KEM | 9/9 (13,213.79 s) |
| Miri, AEAD | 6/6 (214.46 s) |
| Miri, DS bounds | 3/3 (0.42 s) |
| Welch t-test, `n=10,000` | max `\|t\| = 0.737` (smoke signal only) |

Miri does **not** cover full DS signing; the 3/3 figure is the DS bounds
subset. The timing test is not a `dudect`-grade or laboratory result.
Full details and commands: [`docs/testplan.md`](docs/testplan.md).

## Performance

Release on Intel Core i5-14400F (16 hardware threads), Linux x86-64,
`rustc 1.97.1`, `2026-10-30`:

| Operation | Result |
|---|---|
| KEM keygen / encaps / decaps | **795 / 931 / 1124 µs** |
| Hash / streaming / XOF (1 MiB) | **842 / 837 / 827 MB/s** |
| ChaCha20 keystream (1 MiB) | **773 MB/s** |
| AEAD seal / open (1 MiB) | **427 / 434 MB/s** |
| DS sign / verify | **72.0 ms / 3.725 ms** |
| Threaded sign (16 workers) | **18.3 ms**, **3.928×**, byte-identical |

These are local point estimates, not portable guarantees or side-channel
measurements. Reproduce with the command in
[`docs/metrics.md`](docs/metrics.md).

## Security position

HypG is **not** IND-CCA2-proven, UF-CMA-proven, or AEAD-proven for its
exact constructions. The documentation is explicit about the gaps:

- The KEM's FO-style transform has no exact published proof; the
  decapsulation failure probability has only a working `~14.6σ`
  estimate and a 32-trial tripwire, not a `2^-128` analytic bound.
- The DS composition has no exact proof and no signing-volume bound.
  FORS is few-time; the code enforces no signature limit. Signing is
  deterministic in `(sk, msg)`.
- The AEAD is a standard EtM composition but not a standardized
  algorithm; nonce reuse is catastrophic and caller-controlled.
- The CA-PRF is a design hedge; its final BLAKE3 XOF is the
  security-relevant expander, not an independent hardness assumption.
- Branchless source patterns are not a machine-code constant-time proof.
  No power/EM/fault campaign exists.
- No external audit, formal verification, coverage-guided fuzzing
  campaign, or NIST validation exists.

See [`docs/threat-model.md`](docs/threat-model.md),
[`docs/nist-alignment.md`](docs/nist-alignment.md),
[`docs/audit-prep.md`](docs/audit-prep.md), and
[`SECURITY.md`](SECURITY.md).

## Documentation

Start at [`docs/README.md`](docs/README.md). The main entry points:

| Document | Contents |
|---|---|
| [`docs/notation.md`](docs/notation.md) | Formal notation, encodings, security definitions |
| [`docs/parameters.md`](docs/parameters.md) | Authoritative parameter register and size derivations |
| [`docs/design.md`](docs/design.md) | Architecture and rationale |
| [`docs/spec.md`](docs/spec.md) | Normative KEM specification |
| [`docs/spec-ds.md`](docs/spec-ds.md) | Normative DS v2.0.1 specification |
| [`docs/spec-symm.md`](docs/spec-symm.md) | Normative one-shot AEAD |
| [`docs/spec-aead.md`](docs/spec-aead.md) | Streaming AEAD |
| [`docs/spec-hash.md`](docs/spec-hash.md) | Hash/XOF/KDF API |
| [`docs/domains.md`](docs/domains.md) | Domain and tag registry |
| [`docs/api.md`](docs/api.md) | Public API reference |
| [`docs/testplan.md`](docs/testplan.md) | Validation matrix and release checklist |
| [`docs/metrics.md`](docs/metrics.md) | Controlled benchmark and evidence |
| [`docs/lattice-local.md`](docs/lattice-local.md) | Local lattice lab |
| [`docs/estimator.md`](docs/estimator.md) | External hardness-estimation work order |
| [`docs/threading.md`](docs/threading.md) | Threading model |
| [`docs/simd.md`](docs/simd.md) | Scalar/SIMD posture |
| [`docs/nist-alignment.md`](docs/nist-alignment.md) | NIST dimensions vs. compliance gaps |
| [`docs/audit-prep.md`](docs/audit-prep.md) | Audit scope and open questions |
| [`docs/deployment.md`](docs/deployment.md) | Why deployment is prohibited |

## Non-goals

- No production deployment, audit claim, certification, or NIST
  compliance claim.
- No custom symmetric primitive invented for this project: BLAKE3 and
  ChaCha20 are used as designed, with an EtM composition.
- No `unsafe`, external dependency, heap use in the cryptographic
  libraries, or frozen-vector change without a version bump.
- No second-language implementation or standards-submission track.

## Historical material

The v1.0 commit and v1.0 KAT files remain in the repository as historical
evidence. The active frozen files are the four v2.0.0/v2.0.1 files; the
DS `v2.0.0` file is retained but is not the active gate. See
[`docs/parameters.md`](docs/parameters.md#6-frozen-kat-sizes-and-checksums).

## License

HypG is free software licensed under the **GNU General Public License
v3.0 or later** — see [`LICENSE`](LICENSE). Derivative works must remain
free under a compatible license.
