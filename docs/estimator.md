# Lattice-hardness estimation work order

**Status:** the estimator has **not** been run for HypG in this
repository. This file pins the exact inputs, the recommended estimator
workflow, and the acceptance bar for a future production-oriented
analysis. It is a work order, not a result.

## 1. Why this is required

HypG's KEM uses Module-LWE with

```text
n = 256, k = 4, q = 4096, eta = 2,
lattice dimension N = n*k = 1024.
```

The dimensions resemble ML-KEM-1024, but the modulus is `4096`, not
`3329`. ML-KEM-1024 hardness estimates cannot simply be copied:
modulus size, noise distribution, compression, and the module structure
all affect the concrete cost. The signature scheme has a separate
hash-based analysis and is not covered by the lattice estimator.

No in-tree estimator can replace the community Sage
[lattice-estimator](https://github.com/malb/lattice-estimator). The
local `hypg-lattice` lab is a sanity check on LLL and a coarse gap
calculation only. See [lattice-local.md](lattice-local.md).

## 2. Exact estimator input

The shipped secret and error are exactly `CBD(2)`, which in the
estimator API is `ND.CenteredBinomial(2)` (standard deviation 1,
support `-2..2`). The following script is the recommended starting
point:

```python
from estimator import *

# HypG-KEM-1024: Module-LWE flattened to a generic LWE instance.
n, k, q = 256, 4, 4096
N = n * k

params = LWE.Parameters(
    n=N,
    q=q,
    Xs=ND.CenteredBinomial(2),
    Xe=ND.CenteredBinomial(2),
    m=N,
    tag="HypG-KEM-1024 (n=256,k=4,q=4096,CBD2)",
)

print("=== LWE.estimate (default cost/shape model) ===")
estimate = LWE.estimate(params)
print(estimate)

print("=== LWE.estimate.rough (core-SVP comparison) ===")
rough = LWE.estimate.rough(params)
print(rough)
```

Record:

- the estimator commit hash;
- the Sage version;
- the exact script;
- whether `LWE.estimate` or `LWE.estimate.rough` was used;
- the reduction cost model and shape model;
- every reported attack row, including `rop`, `red`, `β`, `d`, and
  memory where present.

The `m=N` choice reflects the 1024 scalar equations in the four
polynomials of the public key. The generic LWE model does not capture
the ring/module structure; it is a standard first approximation, not an
exact Module-LWE analysis. A reviewer should report that limitation and
consider module-aware models if available.

## 3. Distribution modeling checks

The estimator's `CenteredBinomial(2)` has the same support and variance
as the deployed `CBD(2)`. The deployed distribution is

```text
Pr[-2] = 1/16, Pr[-1] = 4/16, Pr[0] = 6/16,
Pr[ 1] = 4/16, Pr[ 2] = 1/16.
```

Do not replace it with a uniform distribution over `[-2,2]` without
labelling the substitution. A uniform distribution has variance 2,
while `CBD(2)` has variance 1; that changes the noise profile.

If a bounded-support estimator path is available, report it as a second
model. Do not silently use a discrete Gaussian of standard deviation 1
as if it were identical to `CBD(2)`; it is a common approximation, but
the tails differ.

## 4. Required comparison points

At minimum, estimate and tabulate:

1. **HypG exact:** `N=1024`, `q=4096`, `CBD(2)`.
2. **ML-KEM-1024 reference:** `N=1024`, `q=3329`, `CBD(2)` with
   ML-KEM's compression assumptions omitted from the LWE core.
3. **Modulus sensitivity:** `q=3329`, `4096`, and one nearby value, with
   all else fixed.
4. **Rank sensitivity:** `k=3`, `k=4`, and `k=5` at the same `n` and
   `q`, to show how the dimension changes the estimate.
5. **Noise sensitivity:** `CBD(2)` versus `CBD(3)` (or the closest
   available bounded distribution), labelled as a sensitivity study,
   not as a proposed parameter change.

The purpose is to quantify the cost of the power-of-two modulus and the
chosen dimension, not to select the most favorable number.

## 5. Cost models

Report at least:

- the default `LWE.estimate` cost and shape models;
- `LWE.estimate.rough` for the conventional core-SVP comparison;
- classical and quantum sieve costs where the estimator exposes them;
- memory, not only `rop`;
- the block size `β` and lattice dimension `d`.

State explicitly whether the numbers are `rop`, `red`, or total cost.
Do not compare a `rop` value from one model with a total cost from
another.

## 6. Proposed acceptance bar

This is an internal project bar for discussing a future profile. It is
not a NIST requirement and not a proof.

- Classical core-SVP cost at least `2^128` operations.
- Quantum core-SVP cost at least `2^116` operations.
- At least 20 bits of margin for estimator/model error.
- Decapsulation failure probability at most `2^-128`, supported by an
  analytic tail bound and a measured sample of at least `10^6` trials.
- Independent review of the FO variant and the Module-LWE parameter
  choice.

If the estimator lands below the bar, do not shrink the margin to keep
the current sizes. Revisit the module rank, modulus, noise distribution,
and compression with a fresh correctness and security analysis. Any
change is a new wire version.

## 7. Interpreting a result

A positive estimator result would mean only that the modeled attacks
cost a certain amount under the estimator's heuristics. It would not
prove IND-CCA2, rule out a new attack, or certify a NIST category. A
negative result would be a serious finding and should block any security
claim until the parameters are changed or the model is shown to be
inapplicable.

Record the exact estimator commit because the project explicitly does
not guarantee API or result stability across commits.

## 8. Current status

| Item | Status |
|---|---|
| Sage installed on the record machine | No |
| Estimator run on HypG parameters | **Not performed** |
| Estimator commit recorded | N/A |
| Classical/quantum cost table | N/A |
| Failure-probability analytic bound | **Not derived** |
| `10^6`-trial failure measurement | **Not performed** |
| Independent parameter review | **Not performed** |

The absence of an estimator result is a first-order gap in the security
case, not a documentation detail. Until it is closed, HypG's KEM
hardness is estimated by analogy only, and the repository must not claim
a bit-security level or NIST Category 5.
