# Public API reference

**Status:** reference for workspace **2.0.0**, DS **2.0.1**. Research
prototype; unaudited; not production-ready.

This page describes the stable surface a caller is expected to use. The
Rustdoc comments in each crate are the precise source; if this page and
the code differ, the code wins.

## 1. Crates and platform

| Crate | `no_std` | Allocates? | Purpose |
|---|---|---|---|
| `hypg-core` | Yes | No | BLAKE3, ChaCha20, CA-PRF, ring arithmetic, constant-time helpers. |
| `hypg-kem` | Yes | No | Module-LWE KEM. |
| `hypg-symm` | Yes | No | One-shot AEAD and hash wrappers. |
| `hypg-aead` | Yes | No | Streaming AEAD. |
| `hypg-ds` | Yes | No | Stateless hash-based signatures. |
| `hypg-hash` | Yes | No | Hash/XOF/KDF API. |
| `hypg-mt` | No (`std`) | Yes | Threaded DS signing. |
| `hypg-kat` | No (`std`) | Yes | KAT generation. |
| `hypg-cli` | No (`std`) | Yes | Operator CLI. |
| `hypg-bench`, `hypg-redteam`, `hypg-lattice` | No (`std`) | Yes | Evaluation harnesses. |

All library crates use `#![forbid(unsafe_code)]` and have no external
dependencies. The workspace MSRV is Rust 1.70.0. The cryptographic
libraries use fixed-size arrays and caller-provided buffers; they do not
allocate.

## 2. Common conventions

- Byte arrays are fixed-size in the public API.
- `from_bytes` constructors are infallible: they accept any bytes of the
  correct length and do not validate algebraic structure.
- Secret types redact `Debug`, avoid `Copy`, compare in constant time
  where equality is provided, and best-effort zeroize on `Drop`.
- "Best-effort" means normal writes plus compiler fences. Safe Rust
  cannot guarantee volatile erasure or protect copies held elsewhere.
- `Option<()>` is the error signal for fallible AEAD operations; there is
  no error enum and no plaintext sentinel.
- `decaps` never fails; see §4.
- All functions are total for correctly sized inputs unless a documented
  panic exists. The cryptographic libraries aim for no panics on
  adversarial bytes.

## 3. `hypg-core`

### 3.1 Parameters

```rust
use hypg_core::params::*;
```

The constants include `STATE_WORDS = 32`, `STATE_BYTES = 256`,
`RULE_WORDS = 8`, `ROUNDS = 32`, `SEED_LEN = 32`, `FAKE_LEN = 32`,
`PK_LEN = 1568`, `CT_LEN = 1440`, `SS_LEN = 32`,
`SK_LEN = 1632`, `HASH_LEN = 32`, `POLY_N = 256`, `MODULE_K = 4`,
`MOD_Q = 4096`, `MOD_Q_MASK = 0x0FFF`, `C1_Q = 1024`,
`C2_Q = 32`, `CBD_ETA = 2`, `CBD_RAND_LEN = 128`,
`POLY_PACKED_LEN = 384`, `C1_PACKED_LEN = 320`,
`C2_PACKED_LEN = 160`, `MSG_LEN = 32`, and derived vector lengths.
The full table is in [parameters.md](parameters.md).

### 3.2 BLAKE3

```rust
use hypg_core::b3::{
    b3_derive_key, b3_expand, b3_hash, b3_kdf, b3_keyed, b3_xof, Hasher,
};

pub fn b3_hash(input: &[u8], out: &mut [u8; 32]);
pub fn b3_xof(out: &mut [u8], input: &[u8]);
pub fn b3_keyed(key: &[u8; 32], input: &[u8], out: &mut [u8; 32]);
pub fn b3_derive_key(context: &str, key_material: &[u8; 32],
                     out: &mut [u8; 32]);
pub fn b3_expand(out: &mut [u8], seed: &[u8; 32], domain: &[u8]);
pub fn b3_kdf(out: &mut [u8], parts: &[&[u8]], domain: &[u8]);
```

`Hasher` supports `new()`, `new_keyed(&key)`, `update(&[u8])`,
`finalize32()`, and `finalize_xof(&mut [u8])`. It is `Clone`; clones
duplicate secret key material. `Debug` is redacted and `Drop` zeroizes
the internal key/state.

`b3_expand` is `XOF(seed || domain)`; `b3_kdf` is
`XOF(domain || parts...)`. Neither adds length separators. See
[spec-hash.md](spec-hash.md).

### 3.3 CA-PRF and ChaCha20

```rust
use hypg_core::caprf::{ca32, ca_expand};
use hypg_core::chacha::{block, xor_in_place};

pub fn ca_expand(out: &mut [u8], seed: &[u8; 32], domain: &[u8]);
pub fn ca32(seed: &[u8; 32], domain: &[u8]) -> [u8; 32];

pub fn block(key: &[u8; 32], nonce: &[u8; 12], counter: u32,
             out: &mut [u8; 64]);
pub fn xor_in_place(key: &[u8; 32], nonce: &[u8; 12], ctr0: u32,
                    buf: &mut [u8]) -> usize;
```

`xor_in_place` returns the number of bytes processed. It stops before the
32-bit counter wraps; callers must treat a short return as a failure.
The KEM and AEAD validate lengths before calling it.

### 3.4 Constant-time helpers

```rust
use hypg_core::ct::{
    ct_eq, ct_select, zeroize, zeroize_nested, zeroize_u16, zeroize_u32,
    zeroize_u64,
};

pub fn ct_eq(a: &[u8], b: &[u8]) -> u8;          // 1 equal, 0 otherwise
pub fn ct_select(out: &mut [u8], a: &[u8], b: &[u8], bit: u8);
```

`ct_eq` returns 0 immediately for unequal public lengths; equal-length
inputs are scanned fully. `ct_select` uses the low bit of `bit` and
zeroizes `out` if lengths mismatch. Zeroization helpers are best-effort
and compiler-fenced; they do not use `unsafe`.

### 3.5 Polynomials

```rust
use hypg_core::poly::{
    cbd_eta2, dot, dot2, uniform_from_packed, Poly, Poly10, Poly5,
};

pub struct Poly(pub [u16; 256]);
pub struct Poly10(pub [u16; 256]);
pub struct Poly5(pub [u16; 256]);

pub fn dot(a: &[Poly], b: &[Poly]) -> Poly;
pub fn dot2(a0: &Poly, a1: &Poly, b0: &Poly, b1: &Poly) -> Poly;
pub fn cbd_eta2(rand128: &[u8; 128]) -> Poly;
pub fn uniform_from_packed(rand384: &[u8; 384]) -> Poly;
```

`Poly` supports `zero`, `add`, `sub`, `mul`, `encode`, `decode`,
`compress10`, `compress5`, `pack12`, `unpack12`. `Poly10` supports
`decompress`, `pack10`, `unpack10`; `Poly5` supports `decompress`,
`pack5`, `unpack5`. The arithmetic is modulo `q = 4096` with negacyclic
multiplication. `dot` is total on unequal lengths (consumes the common
prefix). These are public for testing and research; most callers should
use the KEM.

### 3.6 CA state, rule, and fold helpers

```rust
use hypg_core::{Rule, State};
use hypg_core::step::{init_from_bytes, run};
use hypg_core::fold::{
    assemble_ct, fold_ct_core, fold_pk, state_bytes, CT_CORE_LEN,
};

Rule::expand(seed: &[u8; 32], domain: &[u8]) -> Rule;
run(state: &mut State, rule: &Rule);
init_from_bytes(bytes: &[u8; 256]) -> State;

fold_pk(state: &State) -> [u8; 256];
fold_ct_core(state: &State) -> [u8; 256];
state_bytes(state: &State) -> [u8; 256];
assemble_ct(core: &[u8; 1408], tag: &[u8; 32]) -> [u8; 1440];
```

`fold_*` and `assemble_ct` are total utility functions. They are **not**
the KEM wire format; the KEM uses Module-LWE packings, not these folds.
Do not use them to construct or parse KEM keys/ciphertexts.

## 4. `hypg-kem`

```rust
use hypg_kem::{
    decaps, encaps, keygen, Ciphertext, PublicKey, SecretKey, SharedSecret,
};

pub struct PublicKey(pub [u8; 1568]);
pub struct SecretKey(pub [u8; 1632]);
pub struct Ciphertext(pub [u8; 1440]);
pub struct SharedSecret(pub [u8; 32]);

pub fn keygen(seed: &[u8; 32]) -> (PublicKey, SecretKey);
pub fn encaps(pk: &PublicKey, coins: &[u8; 32])
    -> (Ciphertext, SharedSecret);
pub fn decaps(sk: &SecretKey, ct: &Ciphertext) -> SharedSecret;
pub const fn sizes_ok() -> bool;
```

### 4.1 Types

- `PublicKey` and `Ciphertext` are `Copy`, `Debug`, and value-equal.
- `SecretKey` is `Clone` but **not `Copy`**. `Debug` prints
  `SecretKey { .. }`; equality is constant-time; `Drop` zeroizes.
- `SharedSecret` is `Clone` but **not `Copy`**. `Debug` is redacted;
  equality is constant-time; `Drop` zeroizes.

Methods:

```rust
PublicKey::as_bytes(&self) -> &[u8; 1568]
PublicKey::from_bytes([u8; 1568]) -> PublicKey

SecretKey::as_bytes(&self) -> &[u8; 1632]
SecretKey::from_bytes([u8; 1632]) -> SecretKey
SecretKey::seed_copy(&self) -> [u8; 32]
SecretKey::fake_copy(&self) -> [u8; 32]
SecretKey::public_copy(&self) -> [u8; 1568]
SecretKey::zeroize(&mut self)

Ciphertext::as_bytes(&self) -> &[u8; 1440]
Ciphertext::from_bytes([u8; 1440]) -> Ciphertext

SharedSecret::as_bytes(&self) -> &[u8; 32]
SharedSecret::zeroize(&mut self)
```

The copy accessors return caller-owned secrets; the caller must erase
them. `from_bytes` does not validate consistency.

### 4.2 Usage

```rust
use hypg_kem::{decaps, encaps, keygen};

let seed = [0x42u8; 32];       // CSPRNG output
let (pk, sk) = keygen(&seed);

let coins = [0x07u8; 32];      // fresh CSPRNG output per encapsulation
let (ct, ss1) = encaps(&pk, &coins);
let ss2 = decaps(&sk, &ct);
assert_eq!(ss1, ss2);
```

**`coins` is the FO message `m`.** It is embedded in the ciphertext and
used to derive the PKE randomness. It must be fresh and uniform for
every call. Reusing it under one key repeats `(ct, ss)`.

`decaps` never returns an error. An invalid ciphertext yields a
pseudorandom secret derived from the secret `fake` value and the
ciphertext. A protocol must confirm the shared secret, not assume that a
32-byte return means success.

## 5. `hypg-symm` (one-shot AEAD)

```rust
use hypg_symm::{open, seal, Key, Nonce, TAG_LEN, KEY_LEN, NONCE_LEN,
                MAX_MSG_LEN};

pub struct Key(pub [u8; 32]);
pub struct Nonce(pub [u8; 12]);

pub fn seal(key: &Key, nonce: &Nonce, ad: &[u8], pt: &[u8],
            ct: &mut [u8], tag: &mut [u8; 32]) -> Option<()>;

pub fn open(key: &Key, nonce: &Nonce, ad: &[u8], ct: &[u8],
            tag: &[u8; 32], pt: &mut [u8]) -> Option<()>;
```

`Key` is not `Copy`; `Debug` is redacted; equality is constant-time;
`Drop` zeroizes. `Nonce` is public and `Copy`. `Key::from_bytes`,
`Key::as_bytes`, `Key::zeroize`, `Nonce::from_bytes`, and
`Nonce::as_bytes` are available.

`seal` requires `ct.len() == pt.len()` and `pt.len() <= MAX_MSG_LEN`.
`open` requires `pt.len() == ct.len()` and the same limit. On failure:

- `seal` zeroizes `ct` and `tag`;
- `open` leaves `pt` untouched on authentication failure; it may zeroize
  `pt` if a post-authentication counter failure occurs (not reachable for
  an accepted length).

`MAX_MSG_LEN` is `2^38` bytes. The nonce must be unique per `(key,
message)`. There is no nonce-misuse resistance.

## 6. `hypg-aead` (streaming)

```rust
use hypg_aead::{Key, Nonce, StreamOpener, StreamSealer, TAG_LEN};

impl StreamSealer {
    pub fn new(key: &Key, nonce: &Nonce, ad: &[u8]) -> Self;
    pub fn update(&mut self, pt: &[u8], ct: &mut [u8]) -> Option<()>;
    pub fn finish(mut self, tag: &mut [u8; 32]) -> Option<()>;
}

impl StreamOpener {
    pub fn new(key: &Key, nonce: &Nonce, ad: &[u8]) -> Self;
    pub fn update(&mut self, ct: &[u8], pt: &mut [u8]) -> Option<()>;
    pub fn finish(mut self, tag: &[u8; 32], pt: &mut [u8]) -> Option<()>;
}
```

`update` requires equal input/output lengths and poisons the stream on
mismatch. Associated data must be complete at `new`; it is not streamed.
The sealer's `finish` writes the tag and consumes the sealer. The
opener's `finish` validates the tag and consumes the opener.

The opener's `update` writes **tentative** plaintext. It is valid only
after `finish` returns `Some(())`. On failure, `finish` zeroizes the
supplied plaintext buffer and returns `None`. See
[spec-aead.md](spec-aead.md).

## 7. `hypg-hash`

```rust
use hypg_hash::{
    derive32, expand, hash32, hash64, kdf, keyed32, Hasher,
    DIGEST32_LEN, DIGEST64_LEN, KEY_LEN,
};

pub fn hash32(input: &[u8], out: &mut [u8; 32]);
pub fn hash64(input: &[u8], out: &mut [u8; 64]);
pub fn keyed32(key: &[u8; 32], input: &[u8], out: &mut [u8; 32]);
pub fn derive32(context: &str, key_material: &[u8; 32],
                out: &mut [u8; 32]);
pub fn expand(out: &mut [u8], seed: &[u8; 32], domain: &[u8]);
pub fn kdf(out: &mut [u8], parts: &[&[u8]], domain: &[u8]);
```

`Hasher` is re-exported from `hypg-core::b3`. `hash64` is the first 64
bytes of the BLAKE3 XOF and its first 32 bytes match `hash32`.
`expand`/`kdf` have no length separators; see [spec-hash.md](spec-hash.md).

## 8. `hypg-ds`

```rust
use hypg_ds::{
    ds_keygen, ds_sign, ds_verify, pre_sign, serialize_sig, PreSign,
    SigPk, SigSk, SIG_LEN, SIG_PK_LEN, SIG_SK_LEN,
};

pub struct SigPk(pub [u8; 64]);
pub struct SigSk(pub [u8; 128]);

pub fn ds_keygen(esk: &[u8; 32]) -> (SigPk, SigSk);
pub fn pre_sign(sk: &SigSk, msg: &[u8]) -> PreSign;
pub fn ds_sign(sk: &SigSk, msg: &[u8], sig_out: &mut [u8; 49992]);
pub fn ds_verify(pk: &SigPk, msg: &[u8], sig: &[u8]) -> bool;
pub fn serialize_sig(r: &[u8; 32], fors_sig: &ForsSig,
                     ht_sig: &[LayerSig; 17],
                     sig_out: &mut [u8; 49992]);
```

### 8.1 Types and constants

`SIG_PK_LEN = 64`, `SIG_SK_LEN = 128`, `SIG_LEN = 49,992`.
`SigPk` is public and `Copy`, with `SigPk::as_bytes` and
`SigPk::from_bytes`. `SigSk` is not `Copy`; `Debug` is redacted;
equality is constant-time; `Drop` zeroizes. `SigSk::from_bytes`,
`SigSk::as_bytes`, and `SigSk::zeroize` are available.

`PreSign` has public fields `r`, `pubseed`, `fors_idx`, `tree_idx`,
`leaf`; the master secret `esk` is private and exposed only by
`PreSign::esk(&self) -> &[u8; 32]`. `Debug` omits `esk`; `Drop`
zeroizes it. `PreSign` is produced by `pre_sign`.

`ForsSig` is

```rust
pub type ForsSig = [([u8; 32], [[u8; 32]; 9]); 35];
```

`LayerSig` is `([[u8; 32]; 67], [[u8; 32]; 4])`. These are exported
for the threaded signer and serialization; most callers should use
`ds_sign` and `ds_verify`.

### 8.2 Usage

```rust
use hypg_ds::{ds_keygen, ds_sign, ds_verify, SIG_LEN};

let (pk, sk) = ds_keygen(&[0x43u8; 32]); // 32-byte CSPRNG output
let msg = b"hello hypg-ds";
let mut sig = Box::new([0u8; SIG_LEN]);  // heap-box immediately if
                                         // the stack is constrained
ds_sign(&sk, msg, &mut sig);
assert!(ds_verify(&pk, msg, &sig[..]));
assert!(!ds_verify(&pk, b"other", &sig[..]));
```

Signing is deterministic in `(sk, msg)`. Same key and message produce
the same signature. There is no fresh randomness per signature. The
signature is stateless; the signer keeps no counter.

`ds_verify` returns `false` for any length error, nonzero reserved byte,
invalid FORS/WOTS/XMSS path, or root mismatch. It does not panic on
arbitrary byte slices.

`pre_sign` and `serialize_sig` are public for advanced use and
`hypg-mt`. If you use them directly, you must reproduce the exact FORS
and hypertree assembly; the serial `ds_sign` is the reference.

## 9. `hypg-mt`

```rust
use hypg_mt::{mt_sign, mt_sign_with_workers, worker_count};

pub fn worker_count() -> usize;
pub fn mt_sign(sk: &SigSk, msg: &[u8],
               sig_out: &mut [u8; SIG_LEN]);
pub fn mt_sign_with_workers(sk: &SigSk, msg: &[u8],
                            sig_out: &mut [u8; SIG_LEN],
                            workers: usize);
```

`mt_sign` output is byte-identical to `ds_sign`. `worker_count` reads
`HYPG_MT_WORKERS` when set to `1..=64`; otherwise it uses
`available_parallelism().clamp(1,64)`. `mt_sign_with_workers` clamps to
`[1,64]` and to 52 units. `mt_sign` never panics: a lost worker is
recomputed serially by the join loop.

`hypg-mt` is `std`-only and allocates. The `no_std` DS crate remains the
canonical implementation. See [threading.md](threading.md).

## 10. CLI

```text
hypg-cli keygen [--seed HEX64]
hypg-cli encaps <pk_hex> [--coins HEX64]
hypg-cli decaps <sk_hex> <ct_hex>
hypg-cli seal <key64> <nonce24> <ad_hex> <pt_hex>
hypg-cli open <key64> <nonce24> <ad_hex> <ct_hex> <tag64>
hypg-cli hash <hex>
hypg-cli ds-keygen [--esk HEX64]
hypg-cli ds-sign <sk_hex> <msg_hex>
hypg-cli ds-verify <pk_hex> <msg_hex> <sig_hex>
```

Outputs are `key=value` lines:

- `keygen`: `pk=`, `sk=`;
- `encaps`: `ct=`, `ss=`;
- `decaps`: `ss=`;
- `seal`: `ct=`, `tag=`;
- `open`: `pt=`;
- `hash`: `b3_256=`;
- `ds-keygen`: `ds_pk=`, `ds_sk=`;
- `ds-sign`: `sig=`;
- `ds-verify`: `verify=ok` on success.

Exit codes:

| Code | Meaning |
|---:|---|
| 0 | Success, including KEM decapsulation of an invalid ciphertext. |
| 2 | Usage/input error: bad hex, wrong length, missing value, unknown argument. |
| 3 | Authentication failure: bad AEAD tag or bad signature. |

The CLI reads `/dev/urandom` for missing seeds/coins/esk. It is operator
tooling, not hardened key management; secrets on the command line may be
visible to the OS and shell history. See [deployment.md](deployment.md).

## 11. Error-handling summary

| API | Failure signal | On failure |
|---|---|---|
| `keygen` | None | Always returns keys. |
| `encaps` | None | Always returns `(ct, ss)`. |
| `decaps` | None (implicit rejection) | Pseudorandom `ss`. |
| `seal` | `Option<()>` | Zeroizes `ct`/`tag`. |
| `open` | `Option<()>` | `pt` untouched on auth failure. |
| `StreamSealer::update` | `Option<()>` | Zeroizes chunk, poisons stream. |
| `StreamSealer::finish` | `Option<()>` | Zeroizes tag if poisoned. |
| `StreamOpener::update` | `Option<()>` | Zeroizes tentative chunk, poisons. |
| `StreamOpener::finish` | `Option<()>` | Zeroizes `pt` on failure. |
| `ds_keygen` | None | Always returns keys. |
| `ds_sign` | None | Writes exactly `SIG_LEN` bytes. |
| `ds_verify` | `bool` | `false` on any invalid input. |
| `mt_sign` | None | Never panics; recomputes lost worker chunks. |

## 12. API limitations

- No error enum: `Option<()>` cannot explain why an AEAD operation
  failed. This is intentional to avoid a public oracle; inspect lengths
  before calling if you need diagnostics.
- `from_bytes` does not validate keys. A malformed key may produce
  signatures or decapsulations that are cryptographically useless.
- No `serde`, `alloc`, or `std` integration in the cryptographic crates;
  callers handle serialization, storage, and error reporting.
- No key confirmation, replay protection, or protocol framing.
- No constant-time guarantee at the machine-code level.
- No production support commitment, deprecation policy, or semver
  guarantee beyond the frozen wire versions.

For the normative algorithms behind these APIs, see [spec.md](spec.md),
[spec-ds.md](spec-ds.md), [spec-symm.md](spec-symm.md), and
[spec-hash.md](spec-hash.md).
