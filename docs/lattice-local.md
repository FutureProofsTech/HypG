# Local lattice lab

**Status:** supplementary sanity checks, not a security estimate. The
lab validates that the local LLL/embedding code behaves correctly on
toy instances and computes a coarse arithmetic gap for the shipped
parameters. It does **not** replace the Sage lattice-estimator
work order in [estimator.md](estimator.md).

**Command:** `cargo run -p hypg-lattice`

## 1. Method

The lab uses:

- a classical LLL reduction with `f64` Gram–Schmidt and a Lovász
  parameter of 0.99;
- a textbook primal (Kannan) embedding;
- a Gaussian-heuristic comparison;
- a live KEM round-trip through the shipped code.

All floating-point arithmetic is confined to the `std` binary. The
cryptographic libraries remain float-free. The lab does not implement
BKZ, sieving, or a block-size cost model; those are deliberately left to
the external estimator.

## 2. Results on the record run

| Check | Observed result |
|---|---|
| `L1` LLL 2D exactness vs brute force | 3 fixed bases, 0 mismatches |
| `L2` toy LWE break (`n=8`, `m=16`, `q=257`) | planted 59, found **59**, GH ≈ 42 |
| `L3` dense 32-dim random lattice | shortest/GH ratio **1.09** |
| `L4` real-parameter gap (`d=2049`, `log2 vol=12288`) | GH ≈ 699.6, target ≈ 45.3, gap **15.5×**, LLL slack **2^1020** |
| `L5` live KEM round-trip | `pk=1568 B`, `ct=1440 B` |

## 3. Interpretation

### L1: LLL correctness on 2D

Three fixed 2D bases are reduced and compared with a brute-force
shortest-vector search. The local reduction finds the exact optimum on
all three. This is a correctness check for the LLL implementation, not
evidence about the 1024-dimensional instance.

### L2: the harness can break weak LWE

A toy LWE instance with `n=8`, `m=16`, and `q=257` is constructed with a
planted secret. The primal embedding plus LLL recovers a vector at the
planted scale exactly: planted 59, found 59, while the Gaussian
heuristic is about 42. This demonstrates that the embedding and
recovery logic are wired correctly: the harness is capable of breaking
parameters that are actually weak. It says nothing about the shipped
parameters.

### L3: LLL on a dense lattice

A dense 32-dimensional random lattice is reduced. The shortest vector
found is 1.09 times the Gaussian-heuristic scale. This is the expected
textbook behavior and shows that the reduction does not simply no-op on
dense input. It is not an attack on a cryptographic lattice.

### L4: real-parameter arithmetic

The lab models the shipped KEM as a plain LWE instance with

```text
N = n*k = 1024 unknowns,
m = 1024 samples,
embedding dimension d = m + N + 1 = 2049,
volume q^m = 2^(12*1024) = 2^12288.
```

The Gaussian heuristic gives `GH ≈ 699.6`. The planted target norm
estimate is `sqrt((m+N)*sigma^2 + 1) ≈ 45.3` with `sigma=1`. The ratio is
about 15.5×, and the textbook LLL worst-case bound is about `2^1020`
above the target scale.

This is an arithmetic diagnostic. It says LLL-class reduction is
hopeless against the full instance by a wide margin, which is expected.
It does **not** convert the gap into a BKZ block size or a bit-security
estimate. A 15.5× gap could be closed by stronger reduction; only the
Sage estimator can assign a credible cost.

The model also ignores the module/ring structure, compression, and the
KEM's exact error distribution. Treat L4 as a sanity check, not as a
cryptanalytic result.

### L5: product coupling

The lab performs a live `keygen`/`encaps`/`decaps` round-trip through the
shipped KEM and checks the sizes. This ensures the lab is not detached
from the current constants.

## 4. What the lab does not show

- No BKZ cost, no sieve cost, no quantum cost.
- No claim that the parameters meet NIST Category 5.
- No claim that the LWE instance is hard.
- No attack on the actual KEM.
- No validation of the FO transform, correctness bound, or side
  channels.

## 5. Reproducibility

```bash
cargo run -p hypg-lattice
```

The binary exits nonzero if any of the five checks fails. The output is
deterministic on a given platform; floating-point differences across
platforms may change the last displayed digit but not the pass/fail
thresholds.

For the actual hardness work order, see [estimator.md](estimator.md).
