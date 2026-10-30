# HypG-DS normative specification (v2.0.1)

**Status:** normative description of the implemented stateless
hash-based signature scheme, wire/spec revision **2.0.1**. Research
prototype; unaudited; not production-ready. There is no proof of
UF-CMA/SUF-CMA for this exact composition, no signing-volume analysis,
and no external review.

**Normative sources:** `crates/hypg-ds/src/{params,addr,thash,wots,fors,
xmss,hypertree,slh}.rs`. Frozen vectors:
`crates/hypg-kat/kats-ds/v2.0.1.txt`.

## 1. Scope and profile

The profile is `HypG-DS-256f`:

| Parameter | Value |
|---|---:|
| hash output `n` | 32 bytes |
| total height `h` | 68 |
| layers `d` | 17 |
| per-layer height `h'` | 4 |
| FORS trees `k` | 35 |
| FORS height `a` | 9 |
| WOTS+ `w` | 16 |
| WOTS+ length | 67 |
| public key | 64 bytes |
| secret key | 128 bytes |
| signature | 49,992 bytes |

The scheme uses FORS few-time signatures at the bottom, a 17-layer
XMSS/WOTS+ hypertree above it, and keyed BLAKE3 as the tweakable hash.
It is stateless: no signing state is stored or advanced.

The construction is **SLH-DSA-256f-shaped**, not FIPS 205 conformant.
The hash function, address layout, domain tags, randomizer derivation,
and reserved bytes differ from FIPS 205. See
[nist-alignment.md](nist-alignment.md).

## 2. Data types

```text
SigPk  = [u8; 64]      # root(32) || pubseed(32)
SigSk  = [u8; 128]     # esk(32) || prf(32) || pubseed(32) || root(32)
Sig    = [u8; 49992]
```

`SigSk` is not `Copy`; its `Debug` is redacted; equality is
constant-time; `Drop` best-effort zeroizes it. `PreSign` carries the
master secret `esk` privately, redacts it from `Debug`, and zeroizes it
on drop. `SigPk` is public and may be copied.

The implementation does not validate the consistency of a parsed
`SigSk`. `SigSk::from_bytes` accepts any 128 bytes. A caller that
constructs a secret key from untrusted bytes can produce invalid
signatures; use `ds_keygen` for all normal key generation.

## 3. Address structure

`ADRS` is exactly 32 bytes, with the layout in
[parameters.md](parameters.md#34-ds-address-layout). All fields are
public.

| Type | Name | Field 20 | Field 24 | Field 28 |
|---:|---|---|---|---|
| 0 | `T_FORS` | FORS tree index | FORS leaf index | zero |
| 1 | `T_WOTS_HASH` | keypair index | chain index | absolute chain step |
| 2 | `T_WOTS_PK` | keypair index | L-tree height | L-tree pair index |
| 3 | `T_TREE` | FORS tree index (FORS) or zero (XMSS) | node height | node index |
| 4 | `T_ROOT` | defined, unused | defined, unused | defined, unused |

For XMSS nodes, `layer` and `tree` are set in bytes 0..16 and the
remaining fields identify the node. For FORS addresses, `layer` and
`tree` are zero and field 20 carries the FORS tree index. The `T_ROOT`
type is defined but no current code path emits it.

The 12-byte `tree` field holds a 96-bit little-endian integer. The
hypertree uses at most 68 bits, so the high 28 bits are zero in every
valid address.

## 4. Tweakable hash functions

All three functions are keyed BLAKE3-256 with `pubseed` as the 32-byte
key.

```text
PRF(pubseed, seed, ADRS)
    = KeyedBLAKE3(pubseed, 0x01 || seed || ADRS)

F(pubseed, ADRS, x)
    = KeyedBLAKE3(pubseed, 0x02 || ADRS || x)

H(pubseed, ADRS, left, right)
    = KeyedBLAKE3(pubseed, ADRS || left || right)
```

Sizes:

| Function | Input bytes |
|---|---:|
| `PRF` | 1 + 32 + 32 = 65 |
| `F` | 1 + 32 + 32 = 65 |
| `H` | 32 + 32 + 32 = 96 |

The tags `0x01` and `0x02` are the DS v2.0.1 revision. Before that
revision, `PRF` and `F` both took a 64-byte input and were distinguished
only by field order. If a secret seed happened to equal the address
bytes (or the chain input happened to equal the address bytes), the two
inputs could be byte-identical. The explicit tags remove that
structural collision. `H` is untagged but its 96-byte input is distinct
from both 65-byte inputs.

The key `pubseed` is public. This is keyed hashing for domain separation
and tweak binding, not a secret-key MAC in the signature security game.

## 5. Key generation

```text
KeyGen(esk):
  pubseed = CA-PRF(esk, "HYP-G/v07/ds-pubseed", 32)
  prf     = CA-PRF(esk, "HYP-G/v07/ds-prf", 32)
  root    = HT_Root(pubseed, esk)

  pk = root || pubseed
  sk = esk || prf || pubseed || root
  return (pk, sk)
```

`HT_Root` is the root of the top XMSS layer (`layer = 16`, `tree = 0`),
computed as

```text
HT_Root(pubseed, esk) = XMSS_PK(pubseed, esk, 16, 0).
```

The master secret is `esk`, a 32-byte caller-supplied value with at least
256 bits of entropy. `prf` is derived from `esk`; it is not an
independent random value. `pubseed` is public and is included in `pk`.
The `root` copy in `sk` is used as the public root in the digest; it is
not an independent secret.

## 6. Signing prelude: randomizer and digest

### 6.1 Deterministic randomizer

```text
stream = CA-PRF(prf, "HYP-G/v07/ds-addrnd", 64)
mhash  = BLAKE3(msg)
R      = BLAKE3(stream || mhash)
```

`R` is 32 bytes. The function is deterministic in `(sk,msg)`: no fresh
per-signature entropy is read. Signing the same message twice under the
same key returns the same signature.

There is no fresh hedge. The deterministic derivation is intentional
for KATs and reproducibility. It has privacy implications (signature
equality is visible) and means a fault attack that repeats `R` is not
mitigated by fresh randomness. A randomized variant is future work, not
part of v2.0.1.

### 6.2 Message digest

```text
mhash = BLAKE3(msg)
md[0:32]  = BLAKE3(R || pubseed || root || mhash || LE32(0) || "HYP-G/v07/ds-msghash")
md[32:64] = BLAKE3(R || pubseed || root || mhash || LE32(1) || "HYP-G/v07/ds-msghash")
```

`root` is the public key root. The digest binds the randomizer, the
public seed, the root, and the message. It is 64 bytes; only the first
387 bits are used.

### 6.3 Digest split

Bits are read least-significant first from each digest byte.

```text
for t in [0,35):
    fors_idx[t] = sum_{b=0}^{8} bit(md, 9*t + b) * 2^b

tree_idx = sum_{b=0}^{67} bit(md, 315 + b) * 2^b
leaf     = sum_{b=0}^{3}  bit(md, 383 + b) * 2^b
```

The used range is bits `[0,387)`. Bits `[387,512)` are unused. The
`tree_idx` is a 68-bit integer; the `leaf` is in `[0,16)`.

## 7. FORS few-time signature

FORS uses 35 independent binary trees of height 9. Each tree has
`2^9 = 512` leaves. The FORS signature contains, for each tree, the
selected secret leaf and its 9-node authentication path.

### 7.1 Leaves and tree roots

For tree `t` and leaf `l`:

```text
A = ADRS(layer=0, tree=0, type=0, f20=t, f24=l, f28=0)
leaf_secret(t,l) = PRF(pubseed, esk, A)
```

For a node at height `h` and pair index `p` in tree `t`:

```text
A = ADRS(layer=0, tree=0, type=3, f20=t, f24=h, f28=p)
node = H(pubseed, A, left, right).
```

`FORS_Root(t)` is the root after 9 levels. The FORS public key is

```text
A = ADRS(type=0, f20=0xFFFFFFFF)
FORS_PK = KeyedBLAKE3(pubseed, A || FORS_Root(0) || ... || FORS_Root(34)).
```

This compression input is 32 + 35*32 = 1152 bytes. It is a keyed hash,
not an `H` call. The all-ones field-20 value is a reserved
"root-compression" marker; no FORS tree address uses it.

### 7.2 Signing

For each tree `t`, with selected index `idx[t]`:

```text
unit[t].leaf = leaf_secret(t, idx[t])
for h in [0,9):
    at_h = idx[t] >> h
    sib = at_h XOR 1
    unit[t].auth[h] = node at height h with index sib
```

The signature unit is `leaf` (32 B) || `auth[0]` ... `auth[8]` (32 B each) =
320 bytes. All 35 units form the 11,200-byte FORS signature.

`fors_sign` first checks all 35 indices. If any index exceeds 511, it
returns an all-zero signature without building trees. `fors_sign_one`
does the same for a single index. This is fail-closed behaviour for
internal or malformed calls; indices produced by the digest split are
always in range.

### 7.3 Verification

For each tree, start from the revealed leaf and recompute the root using
the authentication path. At height `h`, the address is

```text
ADRS(type=3, f20=t, f24=h, f28=at/2),
```

where `at` is the current leaf/parent index. If `at` is even, the
computed node is the left child; otherwise it is the right child. After
9 levels, compress the 35 roots exactly as above. Out-of-range indices
return `[0u8;32]`, which cannot equal a real public key root except with
negligible probability.

## 8. WOTS+ one-time signature

### 8.1 Digits and checksum

A 32-byte message is split into 64 nibbles, least-significant nibble
first:

```text
d[i] = (msg[i/2] >> (4*(i mod 2))) & 0x0F,   i in [0,64).
```

The checksum is

```text
csum = sum_{i=0}^{63} (15 - d[i]),   0 <= csum <= 960.
```

Three checksum digits are appended most-significant first:

```text
d[64] = (csum >> 8) & 0x0F
d[65] = (csum >> 4) & 0x0F
d[66] = csum & 0x0F
```

### 8.2 Chains

For a base address carrying `layer`, `tree`, and keypair index in field
20, and chain index `i`:

```text
A = base with type=1, f24=i.
sk[i] = PRF(pubseed, esk, A).
```

The chain function computes 15 `F` calls regardless of the requested
segment:

```text
cur = x; out = x
for s in [0,15):
    step_addr = addr with f28 = start + s
    h = F(pubseed, step_addr, cur)
    cur = h
    out = select(s < steps, h, out)
return out
```

`select(bit,a,b)` returns `a` when `bit` is 1 and `b` when it is 0. The
secret-dependent step count is therefore realized by a full 15-step
computation and a branchless select. Operations use fixed loop bounds.

`WOTS_Sign` calls `Chain(sk[i], start=0, steps=d[i])`.
`WOTS_PKFromSig` calls `Chain(sig[i], start=d[i], steps=15-d[i])`.
`WOTS_PKFromSK` calls `Chain(sk[i], start=0, steps=15)`.
The last call computes the public chain end.

### 8.3 L-tree

The 67 chain ends are compressed into one 32-byte leaf:

```text
level = chain_ends
height = 0
while width > 1:
    for each pair (left,right) at pair index p:
        A = base with type=2, f24=height, f28=p
        next[p] = H(pubseed, A, left, right)
    if the width is odd, the final unpaired node is promoted unchanged
    level = next
    width = ceil(width/2)
    height += 1
```

The odd-node promotion is the DS v2.0.1 change. It matches the FIPS 205
style and avoids hashing a node with itself. The widths are
`67,34,17,9,5,3,2,1`; there are seven compression levels. The final
`level[0]` is the XMSS leaf.

## 9. XMSS layer

An XMSS layer has height 4 and 16 leaves. For keypair index `i`:

```text
base = ADRS(layer, tree, type=0, f20=i)
sk   = WOTS_GenSK(pubseed, esk, base)
pk   = WOTS_PKFromSK(pubseed, sk, base)
leaf = WOTS_LTree(pubseed, pk, base)
```

The Merkle root is built bottom-up. At height `h` and node index `p`:

```text
A = ADRS(layer, tree, type=3, f24=h, f28=p)
node = H(pubseed, A, left, right).
```

There are 4 levels. `XMSS_Sign` builds all 16 leaves, signs the message
with the WOTS key at the selected leaf, and returns the WOTS signature
plus the 4-node authentication path. `XMSS_Verify` recomputes the leaf
from the WOTS signature and climbs using the path. Out-of-range leaf
indices fail closed: signing returns zero arrays and verification
returns `[0u8;32]`.

## 10. Hypertree

The 68-bit tree index selects a path through 17 layers:

```text
tree_i = tree_idx >> (4*(i+1)),     i in [0,17)
leaf_0 = leaf
leaf_i = (tree_idx >> (4*i)) & 15,  i in [1,17)
```

For `i = 16`, `tree_16 = tree_idx >> 68 = 0` because `tree_idx` is
68 bits. The top layer is therefore always tree 0.

Signing starts with the FORS public key as the layer-0 message. For each
layer `i`:

```text
sig_i = XMSS_Sign(pubseed, esk, layer=i, tree=tree_i,
                  leaf=leaf_i, msg=current_message)
current_message = XMSS_Verify(... sig_i ...)
```

The final `current_message` after layer 16 is the hypertree root, which
must equal the public key root. Verification performs the same chain
using the parsed layer signatures.

The top-layer root is computed by `HT_Root` without building the lower
trees. This is possible because the top tree's leaves are WOTS public
keys derived directly from `esk` and `pubseed`; they do not depend on
lower roots. Lower trees are built on demand during signing.

## 11. Signature encoding

```text
offset 0       : R (32)
offset 32      : FORS unit 0 (320)
...
offset 10912   : FORS unit 34 (320), ending at 11232
offset 11232   : layer 0 (2280)
offset 13512   : layer 1 (2280)
...
offset 47712   : layer 16 (2280)
offset 49992   : end
```

More precisely, after `R` and the 35 FORS units, each layer is

```text
0..8        reserved zero bytes
8..2152     WOTS signature (67 * 32)
2152..2280  auth path (4 * 32)
```

Total:

```text
32 + 35*(32 + 9*32) + 17*(8 + 67*32 + 4*32)
= 32 + 11200 + 17*2280
= 49992.
```

All integers in the signature are raw bytes; there is no additional
length prefix. The eight reserved bytes must be zero. Verification scans
all eight bytes with a bitwise OR and rejects the signature if any is
nonzero.

## 12. Verification algorithm

```text
Verify(pk, msg, sig):
  if len(sig) != 49992: return false
  root, pubseed = pk[0:32], pk[32:64]
  R = sig[0:32]
  md = Digest(R, pubseed, root, msg)
  (fors_idx, tree_idx, leaf) = Split(md)
  parse FORS sig from sig[32:11232]
  fors_pk = FORS_Verify(pubseed, fors_idx, fors_sig)
  parse each layer, rejecting nonzero reserved bytes
  root' = HT_Verify(pubseed, tree_idx, leaf, fors_pk, layers)
  return ct_eq(root', root) == 1
```

The `ct_eq` comparison is constant-time over the two 32-byte roots. The
reserved-byte check and length check are on public data and may branch.
No signature field is ignored: every byte is either interpreted or
required to be zero. This is intended to prevent trivial encoding
malleability, but it is not a SUF-CMA proof.

## 13. Security position

### 13.1 Intended assumptions

The intended argument uses:

1. keyed BLAKE3 as a PRF for `PRF` and `F`;
2. keyed BLAKE3 as a collision-resistant/random-oracle hash for `H`,
   FORS root compression, and the digest;
3. the standard FORS few-time and WOTS+ one-time reductions;
4. the XMSS/hypertree composition over 17 layers;
5. a signing-volume assumption limiting FORS leaf reuse and WOTS key
   reuse.

### 13.2 Gaps

- **No exact proof.** The composition is SPHINCS+/SLH-DSA-shaped, but the
  exact hash instantiations, address layout, deterministic `R`, and
  reserved-byte encoding have not been reduced to a published theorem.
- **No signing-volume analysis.** FORS is few-time, not many-time.
  Security degrades as more signatures are produced under one key. The
  implementation enforces no limit and no state. A deployment profile
  would need a concrete bound on signatures per key and a matching
  multi-target analysis.
- **Deterministic signatures.** Same `(sk,msg)` gives the same bytes.
  This is not a nonce-reuse catastrophe of the kind found in ECDSA, but
  it leaks message equality and removes fresh-randomness fault hedging.
- **No independent review.** The parameter shape is conservative, but
  shape is not a proof.
- **No side-channel campaign.** Chain steps, digest splits, and tree
  indices are public after hashing, but the implementation has not been
  measured with `dudect`, power analysis, EM, or fault injection.
- **No formal encoding proof.** The reserved zero bytes and exact length
  remove obvious malleability, but strong unforgeability is not proven.

### 13.3 What is claimed

Only this: the implementation computes the specified bytes; the
deterministic KATs and cross-architecture run agree; sign/verify and
tamper tests pass; invalid indices and malformed signatures fail closed.
No UF-CMA, SUF-CMA, or bit-security level is claimed.

## 14. DS v2.0.1 revision

The 2.0.1 revision changes two things relative to the DS 2.0.0 wire:

1. `PRF` inputs begin with `0x01`; `F` inputs begin with `0x02`.
2. The WOTS+ L-tree promotes an unpaired final node unchanged instead of
   hashing it with itself.

The first change removes a structural collision between the 64-byte
`PRF` and `F` inputs. The second follows the FIPS 205 odd-node rule and
changes every WOTS L-tree root, hence every XMSS root and every
signature. The DS KAT file was regenerated as `v2.0.1.txt`; the
`v2.0.0.txt` DS file remains in the tree as historical evidence but is
not the active gate. KEM, Symm, and Hash wire formats are unchanged by
this revision.

## 15. Frozen vectors and checksum

The DS KAT file contains two vectors:

| Case | Seed | Message length |
|---:|---|---:|
| 0 | `repeat(0x42,32)` | 0 |
| 1 | `repeat(0xFF,32)` | 55 |

Each contains `seed`, `pk`, `sk`, and the full 49,992-byte signature as
hex. The file is 201,015 bytes.

```text
SHA-256(crates/hypg-kat/kats-ds/v2.0.1.txt)
= e88c1bdf54e9390736cd03c1a165616d744a42c48d662880b344c7de3546c813
```

The file is compared byte-for-byte by
`cargo test -p hypg-kat --lib`. The cross-architecture KAT run produced
identical bytes on x86-64 and `qemu-aarch64`; see
[testplan.md](testplan.md).

## 16. Explicit limitations

HypG-DS is not:

- a FIPS 205 implementation or a NIST-approved signature scheme;
- proven UF-CMA or SUF-CMA;
- analyzed for a specific signing volume;
- reviewed by an independent cryptographer;
- validated for side-channel or fault resistance;
- approved for production use.

The parameter sizes are large by design. A 49,992-byte signature and a
72 ms serial signing time on the recorded machine are acceptable for
research evaluation, not automatically acceptable for a deployment
protocol.
