# HypG-AEAD v0.7 Normative Spec (streaming front)

Status: **FROZEN for 1.0**.
Platinum: `no_std`, zero dependencies, bit-exact LE.

## 0. Position: same construction, different schedule

`hypg-aead` is **not a second AEAD construction**. It computes the
exact `hypg-symm` wire format incrementally (`O(1)` extra memory) for
multi-chunk messages:

- Same subkeys: `derive_key("HYP-G/v07/symm-enc" / "symm-mac")`
  (literals duplicated in `hypg-aead`; the stream/`seal` equivalence
  tests fail if they ever diverge — that is the consistency proof).
- Same MAC input order: `nonce ‖ ad ‖ ct ‖ le64(ad_len) ‖ le64(ct_len)`,
  fed to the streaming `Hasher` in that order.
- Same ChaCha keystream: block `i` covers stream bytes
  `[64i, 64i+64)` regardless of chunk boundaries. A partial block
  carries across `update` calls in a 64 B buffer — this is load-bearing:
  restarting the counter per chunk *skips* keystream bytes (caught by
  `stream_matches_oneshot_across_chunkings` during development: a
  1-byte head chunk diverged from one-shot output).
- Same bounds: total stream `< 2³⁸ B` (2³² blocks), enforced by a
  counter gate that fails closed instead of wrapping.

Consequence: `(ct, tag)` from any chunking equals one-shot `seal` for
the concatenated input. The existing symm KATs therefore cover this
wire format; **no new frozen vectors are needed** (equivalence, not
duplication, is tested: 4 KiB across adversarial chunkings incl. empty
chunks, plus 1 MiB in S14).

## 1. Streaming rules

- `ad` is complete at `new()` (streaming `ad` is not supported;
  associated data is small by policy).
- Empty `update` calls are free (no counter advance, no MAC input).
- Any `update` failure (length mismatch, counter exhaustion) poisons
  the stream: the chunk is zeroized and `finish` returns `None`.
- EtM tentative-plaintext rule: opener output is valid **only after
  `finish` returns `Some`**; on `None` the assembled buffer is
  zeroized. Never act on plaintext before `finish` (same shape as
  one-shot `open`, which leaves `pt` untouched on failure).
- Reorder / truncate / duplicate / tamper anywhere breaks the tag
  (single tag covers the full ordered stream + lengths) — S14 games.
- `Drop` wipes key material, nonce copy, and buffered keystream.
  `Hasher` internals are unreachable (same posture as one-shot `seal`).

## 2. Security position

Identical to `hypg-symm` (same bytes, same keys, same tag): 128-bit PQ
target, nonce discipline is the caller's, chunking is invisible on the
wire and therefore contributes no new attack surface — provided the
equivalence tests hold (they are the load-bearing wall between "same
construction" and "second construction"). Auditor must confirm;
prototype, not a claim.

## 3. Public API (Rust)

```rust
pub use hypg_symm::{Key, Nonce, TAG_LEN};
pub struct StreamSealer; // new(key, nonce, ad) -> update(pt, ct) -> finish(tag)
pub struct StreamOpener; // new(key, nonce, ad) -> update(ct, pt) -> finish(tag, pt)
```

`Debug` impls are redacted (lengths/counters only — never key
material, nonce, MAC state, or buffered keystream).
