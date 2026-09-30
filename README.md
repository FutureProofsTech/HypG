# HypG — Post-Quantum Cryptographic Suite

**HypG** is a from-scratch, zero-dependency, 100% safe-Rust
post-quantum cryptographic suite: a Module-LWE key-encapsulation
mechanism, BLAKE3-based hashing, ChaCha20/keyed-BLAKE3 authenticated
encryption (one-shot and streaming), and stateless hash-based
signatures — with deterministic test vectors, an adversarial test
harness, and a fully gated CI pipeline.

> **Status: v1.0.0 frozen research prototype — unaudited, do not deploy.**
> Bit-security is estimated, not confirmed. See [Security](#security)
> and [`SECURITY.md`](SECURITY.md).

## Highlights

- **Four pillars, one core** — KEM, hashing, AEAD, and signatures share
  a single `no_std` core (cellular-automaton expander, Module-LWE
  arithmetic, portable BLAKE3, ChaCha20, constant-time helpers).
- **Zero dependencies, zero `unsafe`** — `cargo tree` shows workspace
  crates only; `#![forbid(unsafe_code)]` in every library, enforced by CI.
- **Bit-exact determinism** — same inputs give same outputs on x86-64,
  AArch64 (verified under QEMU), debug and release builds.
- **Proven performance** — ≈800 MB/s hashing, ≈370 MB/s AEAD,
  60 ms signatures at release on commodity hardware (see [Performance](#performance)).
- **Adversarial testing** — 14 red-team suites: malleability sweeps over
  all 6400 ciphertext bits, 20000-trial failure runs, forgery sweeps,
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
| KEM | Module-LWE (`n=256, k=2, q=2¹²`), FO transform, implicit rejection | `pk`/`ct` 800 B, `sk` 864 B, `ss` 32 B |
| Hash | BLAKE3 as designed (oracle-validated) | 32/64 B digests, arbitrary XOF |
| AEAD | ChaCha20 + keyed-BLAKE3 Encrypt-then-MAC, 32 B tag | key 32 B, nonce 12 B, `ct.len()==pt.len()` |
| Signatures | SLH-shaped FORS + 12-layer XMSS hypertree | `pk` 64 B, `sk` 128 B, `sig` 35456 B |

Parameter history is preserved on the wire: v1.0 freezes the v0.7
parameter generation unchanged (`HYP-G/v07/...` domains, v0.7.0 KAT
labels) — 1.0 reads 0.7 vectors by design.

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
| Malleability (release) | 6400/6400 bit flips change the secret |
| Timing (Welch t-test, n=10000) | max \|t\| ≈ 1.23 (no signal) |
| Miri (core / symm / kem) | UB-clean |
| KATs (4 frozen files) | byte-identical x86-64 / AArch64 / debug / release |
| `cargo audit` | clean — zero dependencies |

Full matrix and per-release checklist: [`docs/testplan.md`](docs/testplan.md).
Local results record: [`docs/metrics.md`](docs/metrics.md).

## Performance

Release on Intel i5-14400F (2026-09-29):

| Operation | Throughput / latency |
|---|---|
| Hash / streaming / XOF (1 MiB) | 836 / 841 / 808 MB/s |
| ChaCha20 keystream | 752 MB/s |
| AEAD seal / open (1 MiB) | 395 / 395 MB/s |
| KEM keygen / encaps / decaps | 199 / 288 / 385 µs |
| Sign / verify | 62 ms / 1.8 ms |
| Threaded sign (16 workers) | 12 ms, byte-identical |

## Security

**This software is a research prototype. Do not use it for real key
exchange, encryption, or signatures.**

- KEM targets Kyber-512-class dimensions, but bit-security is
  **unconfirmed** — the lattice-estimator run is the top backlog item.
- Branchless timing posture only; no power/EM/fault claims.
- The `CA-PRF` automaton mixing is a heuristic hedge; uniformity rests
  on the outer BLAKE3 (random-oracle model).
- KAT vectors pin behavior, not security.

What v1.0 certifies is *process completeness* — everything checkable on
a local machine is checked and gated. See
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
| [`docs/metrics.md`](docs/metrics.md) | Measured results |
| [`docs/deployment.md`](docs/deployment.md) | Test-system rules |
| [`papers/whitepaper.pdf`](papers/whitepaper.pdf) | White paper (design and rationale) |
| [`papers/yellowpaper.pdf`](papers/yellowpaper.pdf) | Yellow paper (formal specification) |
| [`papers/iacr.pdf`](papers/iacr.pdf) | Research paper (IACR style, LNCS class) |

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
