# Lattice security estimation (HypG v0.4.0 parameters)

Goal: confirm Module-LWE hardness before any production claim.
Parameters under test: `n = 256`, `k = 2` (dimension 512),
`q = 4096 = 2^12`, secrets/errors `CBD(eta = 2)` (variance 1,
support `-2..=2`), 1 bit/coeff message (irrelevant to hardness).

## Why this document exists

No in-tree estimator can replace the community Sage
[lattice-estimator](https://github.com/malb/lattice-estimator).
This file pins the exact inputs an auditor must feed it so results are
reproducible, plus the acceptance bar for leaving `0.x`.

## Inputs for the estimator

```python
from estimator import *
from estimator.lwe import estimate as lwe_estimate
# HypG v0.4.0: Module-LWE (n=256, k=2) over Z_{4096}, CBD(2).
# Model the CBD(2) secret/error as: uniform in {-2..2} is NOT uniform;
# use the discrete distribution with probabilities
#   -2: 1/16, -1: 4/16, 0: 6/16, 1: 4/16, 2: 1/16  (variance 1).
n, k, q = 256, 2, 4096
N = n * k            # 512 lattice dimension
std = 1.0            # per-coefficient stddev of secret and error
params = LWE.Parameters(n=N, q=q, Xs=ND.DiscreteGaussian(std), Xe=ND.DiscreteGaussian(std))
lwe_estimate(params)
```

Notes:

- Approximating `CBD(2)` by a discrete Gaussian of stddev 1 is
  conservative-ish for costing (bounded support is slightly easier than
  Gaussian tails for some attacks, harder for others); report both the
  Gaussian model and, if available, the bounded-uniform `{-2..2}` model,
  and take the minimum.
- `q = 4096` is a power of two: ensure the estimator path does not
  assume prime `q` (use the generic LWE estimator, not Kyber-specific
  shortcuts tuned for `3329`).
- Cost models to report: classical BKZ (`sieving + enumeration`) and
  quantum sieve (`Grover`-accelerated SVP oracle). Record blocksize
  `β`, estimated operations, and memory.

## Acceptance bar for a `1.0` claim

- Classical primal/dual cost `≥ 2^128` operations (core-SVP, not just
  BKZ-beta heuristic), quantum model `≥ 2^116`, with `≥ 20`-bit margin
  for estimator error.
- Decapsulation failure `≤ 2^-128` (analytic bound + ≥ 10⁶-trial
  empirical sample; the in-tree 32-trial test is a regression tripwire,
  not the bound).
- If the estimator lands below the bar, parameters must grow
  (`k = 3` and/or `eta = 3`, accepting larger `pk`/`ct`) — never shrink
  the margin to protect sizes.

## Current status (honest)

No estimator run has been performed in-tree (no Sage here). v0.4.0
ships Kyber-512-*shaped* dimensions with a power-of-two `q` deviation;
hardness is **estimated by analogy, not confirmed**. This document is
the work order, not the result.
