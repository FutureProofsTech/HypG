# Audit preparation (HypG v1.0, frozen)

Scope for an external reviewer: everything needed to confirm or refute
prototype readiness, nothing more.

## 1. What to read first (30 minutes)

1. `docs/spec.md` — normative parameters, algorithms, FO-KEM, failure analysis.
2. `docs/threat-model.md` — what is claimed vs. explicitly disclaimed.
3. `docs/estimator.md` — the unperformed hardness confirmation (the top risk).
4. `SECURITY.md` — why the freeze is process-complete but not a security claim.

## 2. Invariants to verify by inspection

- Libraries (`hypg-core`, `hypg-kem`, `hypg-symm`, `hypg-ds`,
  `hypg-hash`, `hypg-aead`) are `#![no_std]`,
  `#![forbid(unsafe_code)]`, zero dependencies (`cargo tree` must show
  only workspace crates; `cargo audit` must be clean).
- No secret-dependent branches, indices, or early returns in the
  `no_std` hot paths (`keygen`/`encaps`/`decaps`, `seal`/`open`,
  stream `update`/`finish`, WOTS+ chains, `ds_sign`/`ds_verify`).
  Loop bounds are public constants; all `if`s are on public
  indices/lengths (CI grep-gates enforce the shape; confirm by reading).
- Reduction of all moduli is mask/shift only (`q = 2^12`, `c1 = 2^10`,
  `c2 = 2^5`); no division/modulo by variables, no floats anywhere in libs.
- `ct_eq` scans all bytes and returns branchless `0/1`; `decaps` selects
  `ss_ok`/`ss_rej` via `ct_select` with no early return; AEAD `finish`
  zeroizes `pt` on mismatch.
- Randomness discipline: caller supplies `seed`/`coins`; every LWE
  secret/error/matrix flows through `CA-PRF` with distinct ASCII domains
  (grep `HYP-G/v07/` against `docs/domains.md` — each use site must have
  a unique suffix; frozen rows are never edited).

## 3. Mechanical checks (commands)

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace --locked                      # 129 pass (see metrics.md)
cargo test --workspace --locked --release
cargo run -p hypg-kat            # must byte-match crates/hypg-kat/kats*/v0.7.0.txt (4 files)
HYPG_BENCH_ITERS=8 cargo run -p hypg-bench
HYPG_BENCH_ITERS=8 HYPG_BENCH_TTEST_N=2000 cargo run -p hypg-bench  # 5-spot t-sweep
cargo run -p hypg-redteam        # S1–S14
cargo run -p hypg-lattice
cargo build -p hypg-core -p hypg-kem -p hypg-symm -p hypg-ds -p hypg-hash -p hypg-aead --target aarch64-unknown-linux-gnu
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps
cargo audit
# local-only (nightly): cargo +nightly miri test -p hypg-symm --lib ; -p hypg-kem --lib (slow)
# MSRV floor: cargo +1.70 test --workspace --locked
```

Cross-arch determinism — **done locally 2026-09-28**: musl static
`hypg-kat` under `qemu-aarch64` is byte-identical to x86-64
(15457/15457 bytes). Reproduce:
`CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER=rust-lld cargo build
-p hypg-kat --target aarch64-unknown-linux-musl`, then diff
`qemu-aarch64 target/aarch64-unknown-linux-musl/debug/hypg-kat`
against the native run. (Requires the musl target + qemu, both present
on the dev PC; CI builds the static binary and diffs when qemu exists.)

Self-audit record, refreshed for the 1.0 freeze (2026-09-29): zero
`panic!`/`todo!`/`unreachable!` and zero `.unwrap()`/`.expect()` in
all lib code including tests (CI-gated; only total `unwrap_or`
fallbacks remain); zero `ne_bytes`/`transmute` (explicit-LE
everywhere, s390x `cargo check` green); heap types banned in `no_std`
libs; `Debug` impls on key-holding stream types are redacted. Every
remaining `if` in non-test lib code is on public indices, lengths, or
protocol constants; no secret indexing anywhere. Removed in earlier
passes: dead `sha3_parts` (the only length-dependent branch),
`hypg-mt` `.expect()`s (serial-fallback refactor), inline-`const`
(MSRV 1.70 fix).

## 4. Adversarial prompts (suggested)

- Re-derive the §5 failure bound independently; confirm the 32-trial test
  is a tripwire, not the argument.
- Attempt key-recovery from `(pk, ct)` via off-the-shelf lattice tooling
  at reduced parameters (e.g. `k = 1`, `n = 64`) to validate the harness
  actually exercises the trapdoor (a break at toy scale that fails to
  scale is the expected healthy result). **Done in-tree at small scale**:
  `cargo run -p hypg-lattice` breaks toy-LWE (`n = 8`, planted 59 →
  found 59) with a validated LLL; see `docs/lattice-local.md`.
- Review `CA-PRF` for domain collisions and length-extension structure;
  confirm the outer BLAKE3 makes output uniform in the ROM even if the CA
  were replaced by the identity function.
- DS composition: confirm the `(h,d,k,a,w)` bound for our exact numbers
  on paper (closed-form FORS/WOTS+/XMSS reductions, `docs/spec-ds.md`
  §6); check ADRS tweaks are unique per call site and the reserved
  signature pad field is rejection-checked at verify.
- AEAD mode: confirm the MAC input layout binds nonce/ad/ct/lengths
  and that verify precedes any plaintext output.
- Confirm `decaps` timing independence structurally (no secret branches)
  rather than from the bench ratio alone (the bench is a smoke signal;
  `dudect`-style testing is still backlog).

## 5. Known limitations (do not file as surprises)

- Bit-security unconfirmed (see `estimator.md`).
- No power/EM/fault analysis.
- Naive `O(n²)` multiply (constant-time by construction, slow by design).
- `sk` zeroization is caller responsibility; the lib offers best-effort
  `zeroize()` only.
