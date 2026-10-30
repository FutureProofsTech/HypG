# Parameter register (workspace 2.0.0; DS 2.0.1)

**Status:** authoritative descriptive register for the shipped
parameters. The Rust constants in `crates/*/src/params.rs` and the
frozen KAT files are the implementation source of truth. Changing a
number here without changing those files is a documentation defect.

The release targets **NIST Category-5 dimensions** for the KEM and
signature profiles. That phrase means the algebraic dimensions resemble
the corresponding NIST profiles; it is **not** a claim of Category-5
security, NIST compliance, or certification. The KEM hardness has not
been confirmed by an external estimator. See
[nist-alignment.md](nist-alignment.md).

## 1. Version and domain identifiers

| Item | Value |
|---|---|
| Workspace version | `2.0.0` |
| KEM wire/spec revision | `2.0.0` |
| Symm wire/spec revision | `2.0.0` (construction unchanged from v0.7) |
| Hash/API revision | `2.0.0` |
| DS wire/spec revision | **`2.0.1`** |
| KEM domain prefix | `HYP-G/v07/` (retained historical prefix) |
| DS randomizer domains | `HYP-G/v07/ds-*` |
| AEAD key-derivation contexts | `HYP-G/v07/symm-enc`, `HYP-G/v07/symm-mac` |

The `v07` domain literals are frozen protocol separators, not a claim
that the current parameter set is v0.7. The active parameter set is the
one in this document. Historical KAT files from v0.4 through v1.0
remain in the tree; the active files are listed in §6.

## 2. KEM parameters (`HypG-KEM-1024` profile)

### 2.1 Algebraic parameters

| Symbol | Value | Notes |
|---|---:|---|
| `n` | 256 | Degree of `X^n + 1`; ring `R_q`. |
| `k` | 4 | Module rank; lattice dimension `n*k = 1024`. |
| `q` | 4096 = `2^12` | Power-of-two modulus; mask-only reduction. |
| `eta` | 2 | `CBD(2)` for `s`, `e`, `r`, `e1`, `e2`. |
| message length | 32 bytes | 256 bits, one bit per polynomial coefficient. |
| message encoding | `bit * 2048` | `q/2` spacing; decode by rounding. |
| `c1` compression | 12 → 10 bits | Rounding to 1024 levels. |
| `c2` compression | 12 → 5 bits | Rounding to 32 levels. |

The modulus is deliberately a power of two. Every reduction is a
12-bit mask, and compression/decompression uses shifts and masks. This
differs from ML-KEM's `q = 3329`; hardness numbers for ML-KEM-1024
cannot be copied to this parameter set.

### 2.2 Byte lengths

| Object | Formula | Bytes |
|---|---|---:|
| `seed` | 32 | 32 |
| `fake` | 32 | 32 |
| `seed_a` | 32 | 32 |
| `pk` | `32 + 4*384` | **1568** |
| `sk` | `32 + 32 + 1568` | **1632** |
| `ct` | `4*320 + 160` | **1440** |
| `ss` | 32 | **32** |
| `b` vector | `4*384` | 1536 |
| `c1` vector | `4*320` | 1280 |
| `c2` | 160 | 160 |
| single 12-bit polynomial | `256*12/8` | 384 |
| single compressed `c1` polynomial | `256*10/8` | 320 |
| single compressed `c2` polynomial | `256*5/8` | 160 |
| CBD input per polynomial | `256*4/8` | 128 |

`pk = seed_a || pack12(b_0) || ... || pack12(b_3)`.
`ct = pack10(compress10(c1_0)) || ... || pack10(compress10(c1_3)) ||
pack5(compress5(c2))`.
`sk = seed || fake || pk`.

### 2.3 Wire layout

| Offset in `pk` | Length | Field |
|---:|---:|---|
| 0 | 32 | `seed_a` |
| 32 | 384 | packed `b[0]` |
| 416 | 384 | packed `b[1]` |
| 800 | 384 | packed `b[2]` |
| 1184 | 384 | packed `b[3]` |
| 1568 | — | end |

| Offset in `ct` | Length | Field |
|---:|---:|---|
| 0 | 320 | packed compressed `c1[0]` |
| 320 | 320 | packed compressed `c1[1]` |
| 640 | 320 | packed compressed `c1[2]` |
| 960 | 320 | packed compressed `c1[3]` |
| 1280 | 160 | packed compressed `c2` |
| 1440 | — | end |

| Offset in `sk` | Length | Field |
|---:|---:|---|
| 0 | 32 | master `seed` |
| 32 | 32 | implicit-rejection `fake` |
| 64 | 1568 | embedded `pk` |
| 1632 | — | end |

### 2.4 Integer and packing details

- A 12-bit coefficient is packed in pairs into 3 bytes: low 8 bits of
  coefficient 0, then the low 4 bits of coefficient 1 in the high nibble
  and the high 4 bits of coefficient 0 in the low nibble, then the high
  8 bits of coefficient 1. This is the usual 2-coefficient/3-byte
  little-endian packing.
- 10-bit and 5-bit coefficients are packed by a generic little-endian
  bitstream: coefficient `i` occupies bits `[i*bits, (i+1)*bits)` of the
  byte stream.
- Compression is rounding, not truncation:
  - `compress10(c) = ((c + 2) >> 2) mod 2^10`, and decompression is
    `c' = compress10(c) << 2`.
  - `compress5(c) = ((c + 64) >> 7) mod 2^5`, and decompression is
    `c' = compress5(c) << 7`.
- In both cases the residual is small and signed modulo `q`; its effect
  on decapsulation correctness is analysed in
  [spec.md](spec.md#6-correctness).

### 2.5 KEM domains

| Domain literal | Use |
|---|---|
| `HYP-G/v07/seed-a` | Derive `seed_a` from master `seed`. |
| `HYP-G/v07/sec-s` | Expand the secret vector `s`. |
| `HYP-G/v07/sec-e` | Expand the error vector `e`. |
| `HYP-G/v07/poly-a` | Expand the `4×4` matrix `A` from `seed_a`. |
| `HYP-G/v07/rand-r` | Expand `r` from the FO randomness seed. |
| `HYP-G/v07/rand-e1` | Expand `e1` from the FO randomness seed. |
| `HYP-G/v07/rand-e2` | Expand `e2` from the FO randomness seed. |
| `HYP-G/v07/fake` | Derive the implicit-rejection key. |
| `HYP-G/v07/r-seed` | BLAKE3 suffix for `H(m \|\| pk \|\| suffix)`. |
| `HYP-G/v07/ss` | Domain for the accepted shared secret. |
| `HYP-G/v07/reject` | Domain for the rejected shared secret. |

The exact byte inputs are in [domains.md](domains.md).

## 3. Signature parameters (`HypG-DS-256f` profile)

### 3.1 Algebraic and tree parameters

| Symbol | Value | Derivation or note |
|---|---:|---|
| `n` | 32 bytes | BLAKE3-256 output; 256-bit hash. |
| `h` | 68 | Total hypertree height. |
| `d` | 17 | Number of XMSS layers. |
| `h'` | 4 | Height per XMSS tree; `2^4 = 16` leaves. |
| `LEAVES` | 16 | `2^h'`. |
| `FORS_K` | 35 | Number of FORS trees. |
| `FORS_A` | 9 | Height of each FORS tree; `2^9 = 512` leaves. |
| `W` | 16 | WOTS+ Winternitz parameter. |
| `WOTS_LEN1` | 64 | `8*n / log2(W) = 256/4`. |
| `WOTS_LEN2` | 3 | Checksum digits. |
| `WOTS_LEN` | 67 | `64 + 3`. |

The total hypertree height is `d*h' = 17*4 = 68`. The digest uses
`35*9 = 315` FORS bits, `68` tree bits, and `4` leaf bits, for 387 used
bits out of 512.

### 3.2 Byte lengths

| Object | Formula | Bytes |
|---|---|---:|
| `pk` (signature public key) | `n + n` | **64** |
| `sk` | `4*n` | **128** |
| FORS signature per tree | `n + a*n` | 320 |
| FORS signature total | `35*320` | **11200** |
| WOTS+ signature | `67*n` | **2144** |
| XMSS auth path | `4*n` | 128 |
| XMSS layer signature | `8 + 2144 + 128` | **2280** |
| hypertree signature | `17*2280` | **38760** |
| full signature `SIG_LEN` | `32 + 11200 + 38760` | **49992** |

The 8-byte field at the start of every layer is reserved and **must be
zero** in a valid signature. It accounts for `17*8 = 136` bytes relative
to the FIPS 205 SLH-DSA-256f signature length of 49,856 bytes. HypG is
not FIPS 205 conformant; the shape is only dimensionally similar.

### 3.3 Key and signature layouts

`SigPk = root(32) || pubseed(32)`.

`SigSk = esk(32) || prf(32) || pubseed(32) || root(32)`.

`Sig = R(32) || FORS(11200) || Layer_0(2280) || ... || Layer_16(2280)`.

Each FORS unit is `leaf_secret` (32 B) || `auth[0]` ... `auth[8]` (32 B each).

Each layer is

```text
reserved_zero(8) || WOTS_signature(67*32) || auth_path(4*32).
```

The reserved field is checked for all-zero bytes during verification. A
nonzero reserved field makes the signature invalid, even if the
cryptographic part would otherwise verify.

### 3.4 DS address layout

`ADRS` is 32 bytes:

| Offset | Length | Field | Encoding |
|---:|---:|---|---|
| 0 | 4 | `layer` | `u32` LE |
| 4 | 12 | `tree` | 96-bit LE (only 68 bits used) |
| 16 | 4 | `type` | `u32` LE |
| 20 | 4 | field 20 | `u32` LE |
| 24 | 4 | field 24 | `u32` LE |
| 28 | 4 | field 28 | `u32` LE |

Address types:

| Value | Name | Used for |
|---:|---|---|
| 0 | `T_FORS` | FORS leaf derivation and root compression. |
| 1 | `T_WOTS_HASH` | WOTS+ chain hashing. |
| 2 | `T_WOTS_PK` | WOTS+ L-tree compression. |
| 3 | `T_TREE` | FORS/XMSS Merkle node hashing. |
| 4 | `T_ROOT` | Defined but currently unused. |

### 3.5 DS hash and domain parameters

| Item | Value |
|---|---|
| Tweakable key | 32-byte `pubseed` |
| `PRF` input | `0x01 \|\| seed(32) \|\| ADRS(32)` = 65 bytes |
| `F` input | `0x02 \|\| ADRS(32) \|\| x(32)` = 65 bytes |
| `H` input | `ADRS(32) \|\| left(32) \|\| right(32)` = 96 bytes |
| Randomizer domain | `HYP-G/v07/ds-addrnd` |
| Message-digest domain | `HYP-G/v07/ds-msghash` |
| `pubseed` derivation | `HYP-G/v07/ds-pubseed` |
| `prf` derivation | `HYP-G/v07/ds-prf` |

`PRF` and `F` have explicit one-byte tags in DS v2.0.1. `H` is untagged
but has a distinct 96-byte arity. See [domains.md](domains.md) for the
full collision analysis.

### 3.6 DS size derivation details

For a WOTS+ digit string of 64 nibbles, the checksum is

```text
csum = sum_{i=0}^{63} (15 - d_i),
```

with `0 <= csum <= 960`. Its three base-16 digits are emitted
most-significant first:

```text
d_64 = (csum >> 8) & 0xF,
d_65 = (csum >> 4) & 0xF,
d_66 = csum & 0xF.
```

Each WOTS+ chain has 15 `F` applications. The L-tree over 67 chain ends
uses `ceil(log2(67)) = 7` levels; an unpaired final node is promoted
unchanged at each odd level. The XMSS tree has 16 leaves and height 4;
the hypertree has 17 such trees stacked.

## 4. AEAD parameters

| Parameter | Value | Note |
|---|---:|---|
| Master key | 32 bytes | Caller-supplied CSPRNG output. |
| Encryption subkey | 32 bytes | `DK("HYP-G/v07/symm-enc", key)`. |
| MAC subkey | 32 bytes | `DK("HYP-G/v07/symm-mac", key)`. |
| Nonce | 12 bytes | Unique per `(key, message)`; caller duty. |
| Tag | 32 bytes | Full keyed-BLAKE3 output. |
| ChaCha20 block | 64 bytes | 10 double-rounds, 20 rounds total. |
| Counter | 32 bits | Initial counter 0. |
| Maximum message | `2^38` bytes | `2^32` blocks × 64 bytes = 256 GiB. |
| AEAD expansion | 32 bytes | Tag only. |

The MAC input is

```text
nonce(12) || ad || ct || LE64(len(ad)) || LE64(len(ct)).
```

The length suffix is mandatory and is included even when `ad` or `ct` is
empty. The one-shot `seal` and `open` functions reject mismatched
buffer lengths and messages outside the block space before doing work.

## 5. Hash and core parameters

| Parameter | Value |
|---|---:|
| BLAKE3 digest | 32 bytes |
| BLAKE3 XOF block | 64 bytes |
| Keyed-BLAKE3 key | 32 bytes |
| CA state | 32 × 64-bit words = 256 bytes |
| CA rule | 8 × 64-bit words = 64 bytes |
| CA rounds | 32 |
| CA state byte order | little-endian |
| ChaCha20 key | 32 bytes |
| ChaCha20 nonce | 12 bytes |

The CA constants are public and fixed in `crates/hypg-core/src/step.rs`:
`RC_BASE = 0x9E3779B97F4A7C15`, `RC_STRIDE = 0xBF58476D1CE4E5B9`, and
`DIFF_MUL = 0xD6E8FEB86659FD93`.

## 6. Frozen KAT sizes and checksums

| File | Bytes | SHA-256 |
|---|---:|---|
| `crates/hypg-kat/kats/v2.0.0.txt` | 28,514 | `3b2dde3d1138c11b54a6880f50ca7b4390071ae53aa94601075f39b2af971d4b` |
| `crates/hypg-kat/kats-symm/v2.0.0.txt` | 3,662 | `91b7942ffb4a3c5da8b8b589268af7b7d1594796b428efdc7e26c567c5f04208` |
| `crates/hypg-kat/kats-hash/v2.0.0.txt` | 923 | `5fa778035ce2e8aa9c89345458ba4da67df4bdbe71a456cbb58026cf9341d9f1` |
| `crates/hypg-kat/kats-ds/v2.0.1.txt` | 201,015 | `e88c1bdf54e9390736cd03c1a165616d744a42c48d662880b344c7de3546c813` |

Total frozen bytes: **234,114**. The DS file is large because each of
its two vectors contains a 49,992-byte signature encoded as 99,984 hex
characters. The KEM file contains three independent vector groups. The
hash file contains three input cases plus keyed-hash and derive-key
anchors. The symm file contains five AEAD cases.

## 7. Parameter-change policy

A parameter change is a wire-format change if it alters any of:

- `n`, `k`, `q`, `eta`, or any packing/compression rule;
- a domain string, tag byte, hash input order, or ADRS field meaning;
- a DS tree shape, digest split, checksum rule, or reserved field;
- an AEAD key-derivation context, MAC input, or length limit;
- a KAT file or KAT format.

Any such change must be accompanied by a new version identifier, new KAT
files, updated documentation, and a cross-architecture equality run.
Adding a test, a benchmark, or an internal zeroization pass is not a
wire-format change and must not alter the frozen bytes.
