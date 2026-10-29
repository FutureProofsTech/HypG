# HypG — Post-Quantum Cryptographic Suite

**HypG** is a from-scratch, zero-dependency, 100% safe-Rust
post-quantum cryptographic suite: a Module-LWE key-encapsulation
mechanism, BLAKE3-based hashing, ChaCha20/keyed-BLAKE3 authenticated
encryption (one-shot and streaming), and stateless hash-based
signatures — with deterministic test vectors, an adversarial test
harness, and a fully gated CI pipeline.

> **Status: v2.0.0 hardened research profile — unaudited, do not deploy.**
> Parameters now match NIST Category-5 *dimensions*, but bit-security is
> estimated, not confirmed. See [Security](#security) and
> [`SECURITY.md`](SECURITY.md).

## Highlights

- **Four pillars, one core** — KEM, hashing, AEAD, and signatures share
  a single `no_std` core (cellular-automaton expander, Module-LWE
  arithmetic, portable BLAKE3, ChaCha20, constant-time helpers).
- **Zero dependencies, zero `unsafe`** — `cargo tree` shows workspace
  crates only; `#![forbid(unsafe_code)]` in every library, enforced by CI.
- **Bit-exact determinism** — same inputs give same outputs on x86-64,
  AArch64 (v2.0 KATs diffed under QEMU), debug and release builds.
- **Measured performance** — ≈800 MB/s hashing, ≈400 MB/s AEAD,
  46 ms signatures at release on commodity hardware (see [Performance](#performance)).
- **Adversarial testing** — 14 red-team suites: malleability sweeps over
  all 11520 ciphertext bits, 20000-trial failure runs, forgery sweeps,
  fault injection, and panic-freedom corpora.

## Architecture

```text
hypg-core ──┬── hypg-kem ─────── KEM (keygen/encaps/decaps)
            ├── hypg-hash ────── hash/XOF/keyed/KDF API
            ├── hypg-symm ─┬──── one-shot AEAD (seal/open)
            │             └── hypg-aead ── streaming AEAD (wire-identical)
            └── hypg-ds ──┬───── signatures (ds_keygen/sign/verify)
                          └── hypg-mt ──── threaded signer (byte-identical)

harnesses: hypg-kat · hypg-bench · hypg-redteam · hypg-lattice · hypg-cli
```

| Pillar | Construction | Sizes |
|---|---|---|
| KEM | Module-LWE (`n=256, k=4, q=2¹²`, dimension 1024), FO transform, implicit rejection | `pk` 1568 B, `ct` 1440 B, `sk` 1632 B, `ss` 32 B |
| Hash | BLAKE3 as designed (oracle-validated) | 32/64 B digests, arbitrary XOF |
| AEAD | ChaCha20 + keyed-BLAKE3 Encrypt-then-MAC, 32 B tag | key 32 B, nonce 12 B, `ct.len()==pt.len()` |
| Signatures | SLH-DSA-256f-shaped FORS 35×9 + 17-layer XMSS hypertree | `pk` 64 B, `sk` 128 B, `sig` 49992 B |

v2.0 is a **breaking parameter-hardening release**: the KEM module rank
moves from `k=2` to `k=4`, and signatures move to a 68-bit hypertree
with FORS `35×9`. The `HYP-G/v07/...` domain strings and the BLAKE3 /
ChaCha20 primitives are unchanged. v1.0 vectors remain in the tree as
historical evidence; the active KAT files are `kats*/v2.0.0.txt`.

## Quick start

```bash
cargo fmt --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace --locked            # 129 tests
cargo run -p hypg-kat                      # must match frozen KAT files
HYPG_BENCH_ITERS=8 cargo run -p hypg-bench
cargo run -p hypg-redteam                  # S1–S14
cargo run -p hypg-lattice                  # lattice lab
```

Operator usage (test systems only, see [`docs/deployment.md`](docs/deployment.md)):

```bash
cargo build --release -p hypg-cli
hypg-cli keygen > keys.txt
hypg-cli encaps <pk_hex> > enc.txt
hypg-cli decaps <sk_hex> <ct_hex>
hypg-cli seal <key64> <nonce24> <ad_hex> <pt_hex>
hypg-cli open <key64> <nonce24> <ad_hex> <ct_hex> <tag64>
hypg-cli hash <hex>
hypg-cli ds-keygen [--esk HEX64]
hypg-cli ds-sign <sk_hex> <msg_hex>
hypg-cli ds-verify <pk_hex> <msg_hex> <sig_hex>
```

Exit codes: `0` success (KEM decapsulation never fails — forgeries yield
a pseudorandom secret instead), `2` usage/input error, `3`
authentication failure.

## Testing

| Gate | Result (this PC) |
|---|---|
| Unit + integration + doc-tests (debug, release, MSRV 1.70) | 129/129 |
| Red-team S1–S14 (defaults and max load) | 14/14 |
| Failure sweep (release) | 20000/20000 clean |
| Malleability (release) | 11520/11520 bit flips change the secret |
| Timing (Welch t-test, n=10000) | max \|t\| ≈ 1.65 (no signal) |
| Miri (core / symm v2.0) | UB-clean; KEM v2.0 re-run pending |
| KATs (4 frozen v2.0.0 files) | byte-identical x86-64 / AArch64 / debug / release |
| `cargo audit` | clean — zero dependencies |

Full matrix and per-release checklist: [`docs/testplan.md`](docs/testplan.md).
Local results record: [`docs/metrics.md`](docs/metrics.md).

## Performance

Release on Intel i5-14400F (2026-10-30, `HYPG_BENCH_ITERS=8`):

| Operation | Throughput / latency |
|---|---|
| Hash / streaming / XOF (1 MiB) | 818 / 820 / 807 MB/s |
| ChaCha20 keystream | 754 MB/s |
| AEAD seal / open (1 MiB) | 397 / 405 MB/s |
| KEM keygen / encaps / decaps | 751 / 914 / 1107 µs |
| Sign / verify | 45.7 ms / 2.25 ms |
| Threaded sign (16 workers) | 12.6 ms, byte-identical |

## Security

**This software is a research prototype. Do not use it for real key
exchange, encryption, or signatures.**

- KEM uses Category-5 *dimensions* (`k=4`, lattice dimension 1024),
  but bit-security is **unconfirmed** — the lattice-estimator run is
  the top backlog item.
- Signatures follow the SLH-DSA-256f shape (256-bit hash, 68-bit
  hypertree, FORS `35×9`), but the composition is not a NIST scheme and
  has not been analysed to the same standard.
- Branchless timing posture only; no power/EM/fault claims.
- The `CA-PRF` automaton mixing is a heuristic hedge; uniformity rests
  on the outer BLAKE3 (random-oracle model).
- KAT vectors pin behavior, not security.

What v2.0 claims is *process completeness* — every gate listed in the
test plan passes locally, with the documented exceptions (notably the
pending v2.0 KEM Miri run). It does **not** certify production
readiness, and it is not “better than NIST standards.” See
[`docs/nist-alignment.md`](docs/nist-alignment.md) for the parameter
mapping and the explicit NIST/production gaps,
[`docs/threat-model.md`](docs/threat-model.md) and
[`docs/audit-prep.md`](docs/audit-prep.md) for the full position and
the road to any security claim.

## Documentation

| Document | Contents |
|---|---|
| [`docs/spec.md`](docs/spec.md) | Normative KEM spec (frozen) |
| [`docs/spec-symm.md`](docs/spec-symm.md) | Normative AEAD spec (frozen) |
| [`docs/spec-aead.md`](docs/spec-aead.md) | Streaming AEAD front (frozen) |
| [`docs/spec-hash.md`](docs/spec-hash.md) | Hashing spec (frozen) |
| [`docs/spec-ds.md`](docs/spec-ds.md) | Signature spec (frozen) |
| [`docs/domains.md`](docs/domains.md) | Domain-separation registry (normative) |
| [`docs/testplan.md`](docs/testplan.md) | Test matrix + release checklist |
| [`docs/nist-alignment.md`](docs/nist-alignment.md) | NIST parameter mapping + production gaps |
| [`docs/metrics.md`](docs/metrics.md) | Measured results |
| [`docs/deployment.md`](docs/deployment.md) | Test-system rules |
| [`papers/whitepaper.pdf`](papers/whitepaper.pdf) | White paper (design and rationale) |
| [`papers/yellowpaper.pdf`](papers/yellowpaper.pdf) | Yellow paper (formal specification) |
| [`papers/iacr.tex`](papers/iacr.tex) | Research paper source (IACR style, LNCS class) |

## Non-goals

- No custom symmetric cryptography, no 16 B tags, no new dependencies,
  no `unsafe`, no frozen-vector changes without a spec version bump.
- No production deployment, no audit claims, no second-language
  implementation, no standards-submission track.

## License

HypG is free software licensed under the **GNU General Public License
v3.0 or later** — see [`LICENSE`](LICENSE). You may copy, distribute,
and modify it under the GPLv3 terms; derivative works must remain free
under a compatible license.
