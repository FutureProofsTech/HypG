# Local lattice analysis (HypG v2.0.0 — supplements, not replaces, `estimator.md`)

Produced by `cargo run -p hypg-lattice` on this PC (i5-14400F).
Methodology: textbook LLL + primal (Kannan) embedding + Gaussian-heuristic
comparisons. No hand-rolled BKZ inequalities — blocksize costing stays a
Sage backlog (`docs/estimator.md`).

## Results (all PASS)

| Check | Result |
|---|---|
| `L1` LLL 2D exactness vs brute force (3 fixed bases) | 0 mismatches |
| `L2` toy-LWE break (`n = 8`, `m = 16`, `q = 257`, dim 25) | planted 59 → found **59** (exact recovery; GH ≈ 42) |
| `L3` dense 32-dim random lattice | shortest/GH ratio **1.09** (LLL reaches ≈GH, textbook behavior) |
| `L4` real-parameter gap (`d = 2049`, `log2vol = 12288`) | GH ≈ 699.6, target ≈ 45.3, gap **15.5×**, LLL worst-case slack **2^1020** |
| `L5` live KEM round-trip | `pk = 1568 B`, `ct = 1440 B` |

Unit tests: `lll_2d_exact4417`, `lll_reduced_form` (size-reduced +
Lovász-ordered output asserted), `toy_breaks`.

## Reading guide

- `L2` proves the harness *can* break weak parameters end-to-end: the
  embedding construction, LLL implementation, and recovery criterion are
  all validated against a planted secret. A break at toy scale that
  fails to scale is the expected healthy result.
- `L3` proves the LLL implementation behaves per theory on dense input
  (ratio ≈ 1). (Lesson learned while building it: a triangular
  Lovász-ordered basis correctly no-ops under LLL — dense input is
  required for a meaningful check.)
- `L4` is arithmetic from the shipped constants, not an attack: the
  15.5× GH/target gap is the margin BKZ must overcome, and the 2^1020
  LLL slack is the rigorous textbook bound showing LLL-class methods
  are hopeless by ~307 orders of magnitude. Converting the gap into a
  BKZ blocksize and a bit-cost is exactly the Sage estimator's job.
