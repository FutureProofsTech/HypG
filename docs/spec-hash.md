# HypG-Hash v0.7 Normative Spec (hashing pillar)

Status: **FROZEN for 2.0**.
Platinum: `no_std`, zero dependencies, bit-exact LE.

## 0. Position: no new cryptography

`hypg-hash` is an ergonomic API over the portable BLAKE3 in
`hypg-core::b3` (oracle-validated against official vectors, including
third-party cross-checks of the empty/`abc`/XOF-64 anchors). There is
no sponge, no custom permutation, no novel mode here — that is
deliberate (see the v1.0 non-goals in the roadmap). This spec pins the
*API contract*; primitive correctness is pinned in `hypg-core`.

(`hypg-symm` re-exports `symm_hash`/`b3_expand`/`b3_kdf` predate this
pillar and stay for compatibility; new code should use `hypg-hash`.)

## 1. Functions (`hypg-hash`)

| Function | Definition | Output |
|---|---|---|
| `hash32(input, out)` | BLAKE3 | 32 B |
| `hash64(input, out)` | First 64 B of the BLAKE3 XOF; `out[..32] == hash32(input)` (root-bytes property, tested) | 64 B |
| `keyed32(key, input, out)` | BLAKE3 keyed mode | 32 B |
| `derive32(context, key_material, out)` | BLAKE3 `derive_key` reference construction | 32 B |
| `expand(out, seed, domain)` | `XOF(seed \|\| domain)`, public lengths | variable |
| `kdf(out, parts, domain)` | `XOF(domain \|\| parts...)`, public lengths | variable |
| `Hasher` | Streaming re-export; `finalize32`/`finalize_xof` agree with one-shots on every input and split pattern (tested) | — |

Widths: `DIGEST32_LEN = 32`, `DIGEST64_LEN = 64`, `KEY_LEN = 32`
(`sizes_ok`).

## 2. Security position

128-bit PQ target inherited from BLAKE3; length-extension is not a
property callers may rely on beyond the XOF prefix relation above
(which is by design, not an attack surface: extending output never
reveals input). Keyed hashing and derivation require 32 B uniform keys
(caller duty, CSPRNG). Auditor must confirm; prototype, not a claim.

## 3. Vectors

`crates/hypg-kat/kats-hash/v2.0.0.txt` (byte-exact gate
`hash_kats_match_frozen_file`): empty/`abc`/1025-byte-pattern inputs
× `hash32`/`hash64`, plus `keyed32` and `derive32` samples. The
empty/`abc`/XOF-64 anchors were cross-checked against third-party
BLAKE3 bindings at freeze time.

## 4. Public API (Rust)

```rust
pub const DIGEST32_LEN: usize = 32;
pub const DIGEST64_LEN: usize = 64;
pub const KEY_LEN: usize = 32;
pub use hypg_core::b3::Hasher;
pub fn hash32(input: &[u8], out: &mut [u8; 32]);
pub fn hash64(input: &[u8], out: &mut [u8; 64]);
pub fn keyed32(key: &[u8; 32], input: &[u8], out: &mut [u8; 32]);
pub fn derive32(context: &str, key_material: &[u8; 32], out: &mut [u8; 32]);
pub fn expand(out: &mut [u8], seed: &[u8; 32], domain: &[u8]);
pub fn kdf(out: &mut [u8], parts: &[&[u8]], domain: &[u8]);
pub const fn sizes_ok() -> bool;
```
