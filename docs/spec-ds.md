# HypG-DS v0.6 Normative Spec (Phase C — implemented this release)

Status: **FROZEN for 1.0 (parameters v0.6, unchanged). Implemented,
unreviewed prototype. Not for deployment.**
Platinum: `no_std`, `forbid(unsafe_code)`, zero dependencies, bit-exact LE.

## 0. Construction: stateless hash-based signatures, SLH-DSA-shaped

FORS few-time signatures + hypertree of XMSS/WOTS+ layers, all hashes
via keyed BLAKE3 (`pubseed` as MAC key) and `CA-PRF` addressing. Stateless (no signer
state to clone — chosen over XMSS-MT in the architecture review).
References: Hülsing et al., SPHINCS+ (Asiacrypt 2019); FIPS 205
(SLH-DSA) for parameter methodology. Security bounds are the cited
closed-form FORS/WOTS+/XMSS reductions — no estimator needed.

## 1. Parameters (`n = 32`, BLAKE3-256 throughout)

| Set | `h` | `d` | `h'` | FORS `(k,a)` | WOTS `w` | Est. sig | Sign cost |
|---|---|---|---|---|---|---|---|
| `HypG-DS-128s` (primary) | 60 | 12 | 5 | (30,7) | 16 | ≈ 34.6 KB | slower |
| `HypG-DS-128f` (fast) | 60 | 20 | 3 | (26,7) | 16 | ≈ 50.4 KB | faster (bench decides) |

Size derivation (primary): FORS sig `k·(a+1)·n = 30·8·32 = 7680 B`;
WOTS+ `len1 = 64`, `len2 = 3`, `len = 67`, sig `67·32 = 2144 B`;
XMSS layer sig ≈ `8` (idx) `+ 2144 + 5·32 = 2312 B`; hypertree
`12 × 2312 = 27744 B`; total `7680 + 27744 + 32 (R) = 35456 B`.
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

- Target 128-bit PQ from BLAKE3-256 collision/second-preimage resistance
  plus FORS few-time-signature bounds per cited analyses, parameterized
  above. Quantum margin follows 256-bit-output Grover assumptions (2^128 preimage).
- Auditor must confirm the `(h,d,k,a,w)` composition bound for our exact
  numbers — closed-form, checkable on paper, tracked as the DS review
  line (no Sage required).
- Backlog at build time: KAT freeze, forgery redteam (S10), bench,
  `hypg-cli sign/verify`, hypertree stack discipline (KB auth paths on
  caller buffers, never `Vec`).

## 7. Explicit non-goals

No stateful XMSS-MT, no lattice signatures, no `n = 16` truncation
(that would halve quantum margin — rejected the same way the 64-bit
rule tensor was).
