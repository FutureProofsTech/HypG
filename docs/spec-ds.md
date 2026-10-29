# HypG-DS v2.0 Normative Spec (Category-5 dimensions)

Status: **FROZEN for 2.0 (parameters v2.0). Implemented, unreviewed
research profile. Not for deployment.**
Platinum: `no_std`, `forbid(unsafe_code)`, zero dependencies, bit-exact LE.

## 0. Construction: stateless hash-based signatures, SLH-DSA-shaped

FORS few-time signatures + hypertree of XMSS/WOTS+ layers, all hashes
via keyed BLAKE3 (`pubseed` as MAC key) and `CA-PRF` addressing. Stateless (no signer
state to clone — chosen over XMSS-MT in the architecture review).
References: Hülsing et al., SPHINCS+ (Asiacrypt 2019); FIPS 205
(SLH-DSA) for parameter methodology. Security bounds are the cited
closed-form FORS/WOTS+/XMSS reductions — no estimator needed.

## 1. Parameters (`n = 32`, BLAKE3-256 throughout)

| Set | `h` | `d` | `h'` | FORS `(k,a)` | WOTS `w` | Sig | Sign cost |
|---|---|---|---|---|---|---|---|
| `HypG-DS-256f` (primary) | 68 | 17 | 4 | (35,9) | 16 | 49992 B | slower |

The previous `HypG-DS-128s` profile (`h=60`, `d=12`, FORS `30×7`) is
retained only in v1.0 KAT files as historical evidence. A fast profile
is not implemented in v2.0.

Size derivation: FORS sig `k·(a+1)·n = 35·10·32 = 11200 B`;
WOTS+ `len1 = 64`, `len2 = 3`, `len = 67`, sig `67·32 = 2144 B`;
XMSS layer sig = `8` (idx) `+ 2144 + 4·32 = 2280 B`; hypertree
`17 × 2280 = 38760 B`; total `32 (R) + 11200 + 38760 = 49992 B`.
`pk = root(32) ‖ pubseed(32) = 64 B`;
`sk = esk(32) ‖ prf(32) ‖ pubseed(32) ‖ root(32) = 128 B`.

## 2. Address structure (`ADRS`, 32 B, LE)

| Bytes | Field |
|---|---|
| 0..4 | layer index |
| 4..16 | tree index (12 B) |
| 16..20 | type (`0` FORS, `1` WOTS-HASH, `2` WOTS-PK, `3` TREE, `4` ROOT) |
| 20..32 | per-type fields (FORS: keypair/tree idx; WOTS: keypair/chain/hash addr; TREE: padding idx) |

Every hash call prefixes its `ADRS` + registry domain (`ds-fors`,
`ds-wots`, `ds-tree`); distinct types never share tweaks.

## 3. Signing (deterministic, hedged structure)

```text
keygen(esk): pubseed = CA-PRF(esk, ds-pubseed)[0..32]; root = hypertree_root(esk, pubseed)
sign(sk, msg):
  stream = CA-PRF(sk.prf, ds-addrnd)            # 64 B
  R  = BLAKE3(ca_stream(prf) || BLAKE3(msg))   # hedged randomizer, deterministic
  md = BLAKE3-stream(R || pk.seed || pk.root || msg-digest)  # 2×32 B counter-bound (64 B)
  (fors_msg, tree_idx, leaf_idx) = split(md)    # k·a + h + h' bits
  fors_sig = FORS.sign(esk, pubseed, fors_msg)
  ht_sig   = hypertree.sign(tree_idx, leaf_idx, FORS.pk)
  sig = R || fors_sig || ht_sig
verify(pk, msg, sig): recompute md, FORS.verify, hypertree.verify vs pk.root
```

## 4. Constant-time rule (binding, new vs KEM)

WOTS+ chain steps depend on secret message digits. Policy: **always
execute all `w−1 = 15` hashes per chain and select via `ct_select`**
(≈8× average cost at `w = 16`, fully branchless). FORS tree selection
uses public indices only. Verification is public-input — normal loops.
This keeps the platinum invariant intact where a Dilithium-style design
(secret-dependent aborts) could not.

## 5. Public API (Rust, planned)

```rust
pub struct SigPk(pub [u8; 64]);
pub struct SigSk(pub [u8; 128]);
pub fn ds_keygen(esk: &[u8; 32]) -> (SigPk, SigSk);
pub fn ds_sign(sk: &SigSk, msg: &[u8], sig_out: &mut [u8; SIG_LEN]); // exact buffer
pub fn ds_verify(pk: &SigPk, msg: &[u8], sig: &[u8]) -> bool; // false on any malformation
```

`sig` length is exact (`SIG_LEN` const); `verify` rejects short/long
inputs without indexing them.

## 6. Security position (honest)

- Target NIST Category-5 dimensions using the SLH-DSA-256f shape:
  256-bit hash output, `h = 68`, `d = 17`, `h' = 4`, FORS `(35,9)`,
  WOTS+ `w = 16`. This matches the *parameters* of a Category-5
  hash-based signature, not its assurance or review status.
- BLAKE3-256 supplies 256-bit preimage resistance (128-bit under
  Grover) and 128-bit classical collision resistance. FORS few-time-signature
  bounds follow the cited closed-form analyses, parameterized above.
- Auditor must confirm the `(h,d,k,a,w)` composition bound for our exact
  numbers — closed-form, checkable on paper, tracked as the DS review
  line (no Sage required).
- Backlog: independent review of the composition bound, side-channel
  laboratory work, and a third-party audit. KAT freeze, forgery
  red-team (S10), bench, and `hypg-cli sign/verify` are complete for
  v2.0.

## 7. Explicit non-goals

No stateful XMSS-MT, no lattice signatures, no `n = 16` truncation
(that would halve quantum margin — rejected the same way the 64-bit
rule tensor was).
