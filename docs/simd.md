# SIMD posture (HypG)

How this project relates to AVX2 / NEON / vector instructions —
and why there are no intrinsics in the tree.

## 1. Findings (verified on this PC, toolchain 1.97.1)

- `core::arch` intrinsics require `unsafe` to call. That alone rules
  them out: `forbid(unsafe_code)` is the project's headline guarantee,
  not a lint setting to work around.
- Portable SIMD (`core::simd`) is **nightly-only** (`portable_simd`,
  issue #86656 — confirmed `E0658` on stable 1.97.1). It cannot ship in
  a stable-pinned workspace. Revisit when it stabilizes (would also
  require an MSRV bump from 1.70; see §4).
- Auto-vectorization was attempted honestly on ChaCha20 and rejected
  with evidence: a batch-4 struct-of-arrays rewrite produced scalar
  rounds in the emitted assembly (160 scalar `rorx` — the full round
  count, zero `ymm` in the loop), and measured **identical throughput**
  (~750 MiB/s) across baseline, `x86-64-v3`, and `native` builds. The
  experiment was reverted; the scalar path stands. `x86-64-v3` does buy
  BMI2 scalar rotates (`rorxl`), which is where the small observed
  deltas come from — not vectorization.

## 2. What this means per ISA

One portable scalar codebase serves every target; the compiler uses
what each target offers. Integer SIMD would be bit-exact anywhere, but
since nothing vectorizes, all targets equally run scalar code:

| Target | Status | Notes |
|---|---|---|
| `x86_64` (baseline) | Full gates | SSE2 baseline codegen |
| `x86_64` + `target-cpu=x86-64-v3` | Builds, full lib tests pass | AVX2/BMI2 available; no measured gain on our kernels — opt-in only |
| `aarch64` (NEON always on) | rlibs + musl static binary; KAT **byte-identical** under `qemu-aarch64` | NEON executes correctly; no NEON-specific source exists or is needed |
| `thumbv7em` (32-bit ARM) | rlibs build | scalar fallback compiles; no runtime harness here |
| `wasm32` | rlibs build | scalar; SIMD128 would need intrinsics (`unsafe`) — not pursued |

## 3. Opt-in build flags (documented, never default)

Default builds target generic CPUs for portable binaries. Where a
deployment controls its hardware, these are safe (output-identical,
KAT-pinned) and occasionally help scalar scheduling:

```bash
RUSTFLAGS="-C target-cpu=x86-64-v3" cargo build --release -p hypg-cli
RUSTFLAGS="-C target-cpu=native" cargo build --release -p hypg-cli  # build machine only
```

CI builds and tests the `x86-64-v3` configuration to keep it from
rotting; it asserts correctness only, never timings.

## 4. MSRV note

Stays at **1.70.0**. Nothing in this program needed newer features;
the day portable SIMD stabilizes, adopting it forces an MSRV bump to
whatever stable release carries it — a deliberate, versioned decision,
not drift. Checker: `cargo +1.70.0 check` is not run here (toolchain
not installed); the bump, when it comes, must be tested, not assumed.

## 5. What would actually move hashing throughput

Fewer hashes per operation (parameter-level), a different hash
(measured and rejected in the BLAKE3 decision record), or genuine
SIMD via one of the two blocked paths above. Scalar micro-tuning of
the current kernels is exhausted to within noise — see `metrics.md`.
