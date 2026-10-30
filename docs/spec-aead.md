# HypG streaming AEAD specification (v2.0)

**Status:** normative description of the implemented streaming front,
revision **2.0.0**. The wire format is byte-identical to the one-shot
AEAD in [spec-symm.md](spec-symm.md). Research prototype; unaudited;
not production-ready.

**Normative source:** `crates/hypg-aead/src/lib.rs`.

## 1. Scope

`hypg-aead` provides incremental encryption and decryption for messages
that are too large or too inconvenient to buffer in full. It reuses the
`hypg-symm` key schedule, ChaCha20 stream, MAC input, and tag format. It
does not define a second wire format.

The streaming API has `O(1)` cryptographic state beyond the caller's
input/output buffers: a 64-byte keystream block, a partial-block offset,
a 64-bit next counter, a running keyed-BLAKE3 state, two length counters,
and a failure flag. It does not allocate.

## 2. Canonical wire format

For the concatenated plaintext `M = M_0 || ... || M_{r-1}` and
associated data `AD`:

```text
enc = DK("HYP-G/v07/symm-enc", K)
mac = DK("HYP-G/v07/symm-mac", K)
C   = ChaCha20(enc, N, counter=0, M)
T   = KeyedBLAKE3(mac, N || AD || C || LE64(len(AD)) || LE64(len(C)))
```

The streaming implementation produces exactly this `C` and `T`. It also
accepts exactly this `C` and `T` under the same key and nonce. Only the
call schedule differs from the one-shot API.

`AD` cannot be streamed: it must be complete when the stream is created.
The implementation treats associated data as a small, caller-buffered
value by policy. Streaming AD would require a different incremental
interface and is not implemented.

## 3. State machines

### 3.1 Sealer

```text
StreamSealer::new(key, nonce, ad) -> sealer
sealer.update(pt_chunk, ct_chunk) -> Option<()>
sealer.finish(&mut tag) -> Option<()>
```

`new` derives the subkeys, initializes keyed BLAKE3 with the MAC key,
absorbs `nonce || ad`, and stores the AD length. It does not process
plaintext.

`update` requires `ct_chunk.len() == pt_chunk.len()`. It copies the
plaintext chunk into the output buffer, XORs the next keystream bytes,
adds the ciphertext length using checked addition, and feeds the
ciphertext bytes to the running MAC. The keystream carries a partial
64-byte block across calls, so non-block-aligned chunk boundaries do not
change the bytes.

`finish` consumes the sealer. It appends `LE64(ad_len) || LE64(ct_len)`
to the running MAC, finalizes the 32-byte tag, and writes it to `tag`.
If the stream was poisoned by an earlier failure, `finish` zeroizes the
tag and returns `None`.

### 3.2 Opener

```text
StreamOpener::new(key, nonce, ad) -> opener
opener.update(ct_chunk, pt_chunk) -> Option<()>
opener.finish(&tag, &mut assembled_pt) -> Option<()>
```

`new` mirrors the sealer's MAC initialization.

`update` requires equal buffer lengths, copies ciphertext into the
tentative plaintext buffer, XORs the keystream, adds the ciphertext
length, and feeds the **ciphertext** (not the tentative plaintext) to the
MAC. The tentative plaintext is not authenticated yet. It must not be
used before `finish` returns `Some(())`.

`finish` requires `pt.len()` to equal the total ciphertext length seen
by `update`. It appends the two little-endian length suffixes, computes
the expected tag, and compares it to the supplied tag with a full-scan
constant-time equality. On mismatch, it zeroizes the entire `pt` buffer
and returns `None`.

## 4. Error and poisoning rules

| Condition | Sealer | Opener |
|---|---|---|
| `update` length mismatch | zeroizes output chunk, poisons stream, `None` | zeroizes tentative chunk, poisons stream, `None` |
| keystream counter exhausted | zeroizes output chunk, poisons stream, `None` | zeroizes tentative chunk, poisons stream, `None` |
| ciphertext length overflow | zeroizes output chunk, poisons stream, `None` | zeroizes tentative chunk, poisons stream, `None` |
| `finish` after poison | zeroizes tag, `None` | zeroizes plaintext, `None` |
| `finish` length disagreement | — | zeroizes plaintext, `None` |
| tag mismatch | — | zeroizes plaintext, `None` |
| success | writes tag, `Some(())` | validates, leaves plaintext, `Some(())` |

A poisoned stream never recovers. Callers must discard it and start a
new stream. The output buffer of a failed `update` is zeroized; it is
not partially valid.

The counter limits are the same as the one-shot AEAD: at most `2^32`
ChaCha20 blocks, hence at most `2^38` bytes. The streaming implementation
checks the 64-bit internal counter against `u32::MAX` and fails closed
rather than wrapping. It also uses checked addition for the ciphertext
length counter.

## 5. Equivalence with one-shot

For any sequence of chunk boundaries whose concatenation is `M`, the
streaming sealer returns the same `C` and `T` as one-shot `seal`. For any
sequence whose concatenation is `C`, the opener returns the same `M` as
one-shot `open`. This is a byte-level equivalence, not merely a
semantic one.

The implementation tests empty chunks, one-byte chunks, block-boundary
splits (`63,64,65`), multi-chunk splits, duplicate empty chunks, and
1 MiB streams. The one-shot KATs are the canonical vectors for both
APIs.

## 6. Security position

The security properties and caveats are those of
[spec-symm.md](spec-symm.md):

- EtM with a 256-bit tag;
- nonce uniqueness is mandatory;
- no nonce-misuse resistance;
- no key commitment claim;
- no proof for the exact composition;
- no side-channel laboratory evaluation.

Streaming adds one important API-level caveat: **tentative plaintext**.
The opener writes decrypted bytes into the caller's buffer before
authentication completes. Those bytes are not trustworthy until
`finish` returns `Some(())`. A caller that parses, displays, executes, or
transmits tentative plaintext before `finish` has bypassed the AEAD's
integrity guarantee.

On failure, the implementation zeroizes the full `pt` buffer supplied to
`finish`. It cannot zeroize copies the caller may have made from earlier
`update` calls. A caller that releases tentative plaintext is
responsible for erasing those copies.

## 7. API contracts

```rust
pub struct StreamSealer { /* private */ }
pub struct StreamOpener { /* private */ }

impl StreamSealer {
    pub fn new(key: &Key, nonce: &Nonce, ad: &[u8]) -> Self;
    pub fn update(&mut self, pt: &[u8], ct: &mut [u8]) -> Option<()>;
    pub fn finish(mut self, tag: &mut [u8; TAG_LEN]) -> Option<()>;
}

impl StreamOpener {
    pub fn new(key: &Key, nonce: &Nonce, ad: &[u8]) -> Self;
    pub fn update(&mut self, ct: &[u8], pt: &mut [u8]) -> Option<()>;
    pub fn finish(mut self, tag: &[u8; TAG_LEN], pt: &mut [u8]) -> Option<()>;
}
```

Both types redact key material from `Debug` and best-effort zeroize
subkeys, nonce copies, and buffered keystream on drop. A dropped stream
is not authenticated and must not be treated as a completed operation.

## 8. Explicit limitations

The streaming API is not:

- a substitute for message framing or replay protection;
- safe to use with nonce reuse;
- safe to consume before `finish`;
- a standards-compliant AEAD;
- evaluated for timing, power, EM, or fault leakage;
- a production key-management or storage layer.

See [deployment.md](deployment.md) for the operational conditions that
would have to be met before any real use.
