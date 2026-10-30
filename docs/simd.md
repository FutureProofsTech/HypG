# SIMD and code-generation posture

**Status:** descriptive. The implementation is scalar. No SIMD
intrinsics are used.

## 1. Findings

- **`core::arch` intrinsics require `unsafe`.** The workspace uses
  `#![forbid(unsafe_code)]` in every library. Intrinsics are therefore
  excluded by policy, not merely deferred.
- **Portable SIMD is not available on the MSRV.** `core::simd` /
  `portable_simd` is a nightly feature. The workspace supports stable
  Rust 1.70, so it cannot ship a portable-SIMD implementation without
  raising the MSRV and accepting a nightly dependency. Neither is part
  of v2.0.
- **No explicit vectorization is present.** BLAKE3, ChaCha20, the
  polynomial arithmetic, and the DS hash paths are scalar code. The
  compiler may auto-vectorize some loops, but the project does not rely
  on it and has not measured it as a performance claim.
- **An earlier auto-vectorization experiment did not pay off.** A
  batch-4 struct-of-arrays ChaCha20 rewrite produced scalar rounds in
  the emitted assembly and no measured throughput gain, so it was
  reverted. That experiment is historical; it is not part of the current
  build.

## 2. Per-target status

| Target | Status | Notes |
|---|---|---|
| `x86_64` baseline | Full gates | Portable scalar build. |
| `x86_64` + `target-cpu=x86-64-v3` | Library tests pass | AVX2/BMI2 codegen; no claim of vectorized kernels. |
| `aarch64-unknown-linux-gnu` | Builds | Cross-compile gate. |
| `aarch64-unknown-linux-musl` | Builds and runs under `qemu-aarch64` | KAT byte-identical to x86-64. |
| `thumbv7em-none-eabihf` | Builds | Embedded target check. |
| `wasm32-unknown-unknown` | Builds | Scalar; no SIMD128 path. |
| `s390x-unknown-linux-gnu` | `cargo check` | Compile-only; no runtime sysroot. |

The cross-architecture KAT equality is evidence of portable bytes, not
of native performance or native runtime validation on each target.

## 3. Why scalar is acceptable for this profile

The project's priorities are reviewability, zero external dependencies,
safe Rust, and `no_std` portability. A scalar implementation:

- has a smaller trusted code base;
- avoids architecture-specific code and feature detection;
- keeps the KAT bytes identical across targets;
- avoids the alignment and endianness pitfalls of hand-written SIMD;
- remains compatible with the stable MSRV.

The cost is throughput. The recorded BLAKE3 rate is about 842 MB/s for
1 MiB on the test machine, ChaCha20 about 773 MB/s, and the AEAD about
427–434 MB/s. These are acceptable for a research prototype, not a
high-performance server target.

## 4. Optional build flags

Default builds target a generic CPU. A deployment that controls its
hardware may test:

```bash
RUSTFLAGS="-C target-cpu=x86-64-v3" cargo build --release -p hypg-cli
RUSTFLAGS="-C target-cpu=native" cargo build --release -p hypg-cli
```

`target-cpu=native` produces a binary tied to the build machine. Do not
distribute it to heterogeneous hardware. These flags are not required
for correctness, and the project makes no performance promise for them.

CI tests the `x86-64-v3` configuration for library correctness. It does
not gate on timing.

## 5. MSRV

The workspace declares `rust-version = "1.70.0"`. The full 146-test
suite passes on `cargo 1.70.0`; see [testplan.md](testplan.md). Adopting
portable SIMD or any newer language feature would require a deliberate
MSRV bump, new CI coverage, and updated documentation.

## 6. What would improve throughput

In rough order of likely impact:

1. A reviewed NTT or Karatsuba path for polynomial multiplication,
   which is the KEM bottleneck.
2. A reviewed SIMD BLAKE3 implementation, which would require a
   controlled `unsafe` exception or a dependency, both currently
   forbidden.
3. Parameter-level reductions in hash count, which are security-profile
   changes and require a new wire version.
4. Better scheduling of the existing tree builds in `hypg-mt`, which
   affects only signing latency.

None of these is a security improvement by itself. A faster implementation
can be less safe if it introduces secret-dependent branches, alignment
assumptions, or new dependencies. Any such change requires a fresh
side-channel and correctness review.

## 7. Non-claims

The project does not claim:

- that scalar code is constant-time;
- that the compiler does not auto-vectorize in a secret-dependent way;
- that `target-cpu` flags preserve timing behaviour;
- that SIMD would be bit-identical without testing;
- that the measured throughput generalizes to other CPUs.
