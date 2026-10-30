//! Portable BLAKE3: hash, XOF, keyed hash, key derivation.
//!
//! `no_std`, zero-dependency, `forbid(unsafe_code)`. Scalar only (no SIMD
//! — that is the official crate's job; this module trades its ~1.5× for
//! zero dependencies and no `unsafe`). Chunk tree, parent stacking, and
//! root-output chaining follow the reference algorithm exactly; every
//! mode below is pinned against official-crate oracle vectors (see tests;
//! vectors captured from `blake3 v1.8.7`, provenance in commit history).
//!
//! Streaming [`Hasher`] needs no allocation: chunk state (64 B) plus a
//! fixed 54-deep chaining-value stack (worst case 2⁵⁴ chunks).
//!
//! Intentional `as` casts: word/byte packing on fixed geometry
//! (branchless, total — `try_from().unwrap_or` where fallible).

#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss,
    clippy::cast_lossless
)]

use core::fmt;

use crate::ct::{zeroize, zeroize_u32};

const IV: [u32; 8] = [
    0x6A09_E667,
    0xBB67_AE85,
    0x3C6E_F372,
    0xA54F_F53A,
    0x510E_527F,
    0x9B05_688C,
    0x1F83_D9AB,
    0x5BE0_CD19,
];

const MSG_PERM: [usize; 16] = [2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8];

const CHUNK_START: u32 = 1;
const CHUNK_END: u32 = 2;
const PARENT: u32 = 4;
const ROOT: u32 = 8;
const KEYED_HASH: u32 = 16;
const DERIVE_KEY_CONTEXT: u32 = 32;
const DERIVE_KEY_MATERIAL: u32 = 64;

const BLOCK_LEN: usize = 64;
const CHUNK_LEN: usize = 1024;
const OUT_LEN: usize = 32;
/// CV stack depth: covers up to 2⁵⁴ chunks with no allocation.
const STACK_DEPTH: usize = 54;

fn g(state: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize, mx: u32, my: u32) {
    state[a] = state[a].wrapping_add(state[b]).wrapping_add(mx);
    state[d] = (state[d] ^ state[a]).rotate_right(16);
    state[c] = state[c].wrapping_add(state[d]);
    state[b] = (state[b] ^ state[c]).rotate_right(12);
    state[a] = state[a].wrapping_add(state[b]).wrapping_add(my);
    state[d] = (state[d] ^ state[a]).rotate_right(8);
    state[c] = state[c].wrapping_add(state[d]);
    state[b] = (state[b] ^ state[c]).rotate_right(7);
}

fn round_fn(state: &mut [u32; 16], m: &[u32; 16]) {
    g(state, 0, 4, 8, 12, m[0], m[1]);
    g(state, 1, 5, 9, 13, m[2], m[3]);
    g(state, 2, 6, 10, 14, m[4], m[5]);
    g(state, 3, 7, 11, 15, m[6], m[7]);
    g(state, 0, 5, 10, 15, m[8], m[9]);
    g(state, 1, 6, 11, 12, m[10], m[11]);
    g(state, 2, 7, 8, 13, m[12], m[13]);
    g(state, 3, 4, 9, 14, m[14], m[15]);
}

/// Raw compression: 16-word output (callers select chaining vs XOF halves).
fn compress(
    cv: &[u32; 8],
    block_words: &[u32; 16],
    counter: u64,
    block_len: u32,
    flags: u32,
) -> [u32; 16] {
    let mut state = [0u32; 16];
    state[..8].copy_from_slice(cv);
    state[8..12].copy_from_slice(&IV[..4]);
    state[12] = counter as u32;
    state[13] = (counter >> 32) as u32;
    state[14] = block_len;
    state[15] = flags;
    let mut m = *block_words;
    let mut r = 0usize;
    while r < 7 {
        round_fn(&mut state, &m);
        let mut p = [0u32; 16];
        let mut i = 0usize;
        while i < 16 {
            p[i] = m[MSG_PERM[i]];
            i += 1;
        }
        m = p;
        r += 1;
    }
    let mut i = 0usize;
    while i < 8 {
        state[i] ^= state[i + 8];
        state[i + 8] ^= cv[i];
        i += 1;
    }
    state
}

/// Chaining value (first 8 words) of a compression.
fn chaining_value(
    cv: &[u32; 8],
    block_words: &[u32; 16],
    counter: u64,
    block_len: u32,
    flags: u32,
    out: &mut [u32; 8],
) {
    let state = compress(cv, block_words, counter, block_len, flags);
    out.copy_from_slice(&state[..8]);
}

fn words_from_bytes(block: &[u8]) -> [u32; 16] {
    let mut words = [0u32; 16];
    let mut i = 0usize;
    while i < 16 {
        let mut w = [0u8; 4];
        let mut k = 0usize;
        while k < 4 {
            let idx = 4 * i + k;
            if idx < block.len() && idx < BLOCK_LEN {
                w[k] = block[idx];
            }
            k += 1;
        }
        words[i] = u32::from_le_bytes(w);
        i += 1;
    }
    words
}

fn words_to_bytes(words: &[u32], out: &mut [u8]) {
    let mut i = 0usize;
    while i < words.len() && 4 * i < out.len() {
        let b = words[i].to_le_bytes();
        let mut k = 0usize;
        while k < 4 && 4 * i + k < out.len() {
            out[4 * i + k] = b[k];
            k += 1;
        }
        i += 1;
    }
}

/// Parent CV: `key` as chaining value, `PARENT` flag (plus mode flags).
fn parent_cv(key: &[u32; 8], left: &[u8; 32], right: &[u8; 32], flags: u32, out: &mut [u8; 32]) {
    let mut block = [0u32; 16];
    let mut i = 0usize;
    while i < 8 {
        block[i] =
            u32::from_le_bytes([left[4 * i], left[4 * i + 1], left[4 * i + 2], left[4 * i + 3]]);
        block[8 + i] = u32::from_le_bytes([
            right[4 * i],
            right[4 * i + 1],
            right[4 * i + 2],
            right[4 * i + 3],
        ]);
        i += 1;
    }
    let mut cv = [0u32; 8];
    chaining_value(key, &block, 0, BLOCK_LEN as u32, flags | PARENT, &mut cv);
    let mut bytes = [0u8; 32];
    words_to_bytes(&cv, &mut bytes);
    out.copy_from_slice(&bytes);
}

/// Streaming hasher: chunk state + fixed CV stack. No allocation, `no_std`.
///
/// The struct holds the MAC key and all intermediate chaining state, so
/// `Debug` is deliberately redacted and `Drop` best-effort zeroizes the
/// keyed material.
#[derive(Clone)]
pub struct Hasher {
    key: [u32; 8],
    flags: u32,
    cv: [u32; 8],
    chunk_counter: u64,
    buf: [u8; BLOCK_LEN],
    buf_len: usize,
    blocks_compressed: u32,
    stack: [[u8; 32]; STACK_DEPTH],
    stack_len: usize,
}

impl fmt::Debug for Hasher {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Never render `key`, `cv`, `buf`, or `stack`.
        f.write_str("Hasher { .. }")
    }
}

impl Drop for Hasher {
    fn drop(&mut self) {
        zeroize_u32(&mut self.key);
        zeroize_u32(&mut self.cv);
        zeroize(&mut self.buf);
        let mut i = 0usize;
        while i < STACK_DEPTH {
            zeroize(&mut self.stack[i]);
            i += 1;
        }
    }
}

impl Hasher {
    /// Unkeyed hash mode.
    #[must_use]
    pub const fn new() -> Self {
        Self::with_key(&IV, 0)
    }

    /// Keyed hash mode (`key` = 32-byte MAC key as words).
    #[must_use]
    pub const fn new_keyed(key: &[u8; 32]) -> Self {
        // `const` word decoding without loops.
        Self::with_key(
            &[
                (key[0] as u32)
                    | ((key[1] as u32) << 8)
                    | ((key[2] as u32) << 16)
                    | ((key[3] as u32) << 24),
                (key[4] as u32)
                    | ((key[5] as u32) << 8)
                    | ((key[6] as u32) << 16)
                    | ((key[7] as u32) << 24),
                (key[8] as u32)
                    | ((key[9] as u32) << 8)
                    | ((key[10] as u32) << 16)
                    | ((key[11] as u32) << 24),
                (key[12] as u32)
                    | ((key[13] as u32) << 8)
                    | ((key[14] as u32) << 16)
                    | ((key[15] as u32) << 24),
                (key[16] as u32)
                    | ((key[17] as u32) << 8)
                    | ((key[18] as u32) << 16)
                    | ((key[19] as u32) << 24),
                (key[20] as u32)
                    | ((key[21] as u32) << 8)
                    | ((key[22] as u32) << 16)
                    | ((key[23] as u32) << 24),
                (key[24] as u32)
                    | ((key[25] as u32) << 8)
                    | ((key[26] as u32) << 16)
                    | ((key[27] as u32) << 24),
                (key[28] as u32)
                    | ((key[29] as u32) << 8)
                    | ((key[30] as u32) << 16)
                    | ((key[31] as u32) << 24),
            ],
            KEYED_HASH,
        )
    }

    const fn with_key(key: &[u32; 8], flags: u32) -> Self {
        Self {
            key: *key,
            flags,
            cv: *key,
            chunk_counter: 0,
            buf: [0u8; BLOCK_LEN],
            buf_len: 0,
            blocks_compressed: 0,
            stack: [[0u8; 32]; STACK_DEPTH],
            stack_len: 0,
        }
    }

    fn start_flag(&self) -> u32 {
        if self.blocks_compressed == 0 {
            CHUNK_START
        } else {
            0
        }
    }

    /// Unkeyed hasher with explicit mode flags (e.g. derive-key context).
    fn with_flags(flags: u32) -> Self {
        Self {
            key: IV,
            flags,
            cv: IV,
            chunk_counter: 0,
            buf: [0u8; BLOCK_LEN],
            buf_len: 0,
            blocks_compressed: 0,
            stack: [[0u8; 32]; STACK_DEPTH],
            stack_len: 0,
        }
    }

    /// Absorb input (any length, any call pattern).
    pub fn update(&mut self, mut input: &[u8]) {
        while !input.is_empty() {
            if self.chunk_used() == CHUNK_LEN {
                // Full chunk with more input coming: seal it into the tree.
                let cvb = self.chunk_output_cv();
                let total = self.chunk_counter + 1;
                self.push_chunk_cv(&cvb, total);
                self.chunk_counter += 1;
                self.reset_chunk();
                continue;
            }
            let take = (CHUNK_LEN - self.chunk_used()).min(input.len());
            self.absorb_part(&input[..take]);
            input = &input[take..];
        }
    }

    /// Bytes absorbed in the current chunk.
    fn chunk_used(&self) -> usize {
        let used = self.blocks_compressed as usize * BLOCK_LEN + self.buf_len;
        debug_assert!(used <= CHUNK_LEN);
        used
    }

    /// Reset chunk state for the next chunk (counter already advanced).
    fn reset_chunk(&mut self) {
        self.cv = self.key;
        self.buf = [0u8; BLOCK_LEN];
        self.buf_len = 0;
        self.blocks_compressed = 0;
    }

    /// Absorb `data` (never completes a chunk: caller guarantees room).
    /// Full buffered blocks compress only when more bytes follow in this
    /// call, so the tail block always stays buffered for chaining/flags.
    fn absorb_part(&mut self, mut data: &[u8]) {
        if self.buf_len > 0 {
            let want = BLOCK_LEN - self.buf_len;
            let take = want.min(data.len());
            self.buf[self.buf_len..self.buf_len + take].copy_from_slice(&data[..take]);
            self.buf_len += take;
            data = &data[take..];
            if self.buf_len == BLOCK_LEN && !data.is_empty() {
                self.compress_buffered();
            }
        }
        while data.len() > BLOCK_LEN {
            let words = words_from_bytes(&data[..BLOCK_LEN]);
            let mut next = [0u32; 8];
            chaining_value(
                &self.cv,
                &words,
                self.chunk_counter,
                BLOCK_LEN as u32,
                self.flags | self.start_flag(),
                &mut next,
            );
            self.cv = next;
            self.blocks_compressed += 1;
            data = &data[BLOCK_LEN..];
        }
        if !data.is_empty() {
            self.buf[..data.len()].copy_from_slice(data);
            self.buf_len = data.len();
        }
    }

    /// Compress the full buffered block (only when more input follows).
    fn compress_buffered(&mut self) {
        let words = words_from_bytes(&self.buf);
        let mut next = [0u32; 8];
        chaining_value(
            &self.cv,
            &words,
            self.chunk_counter,
            BLOCK_LEN as u32,
            self.flags | self.start_flag(),
            &mut next,
        );
        self.cv = next;
        self.buf = [0u8; BLOCK_LEN];
        self.buf_len = 0;
        self.blocks_compressed += 1;
    }

    /// Push a completed chunk CV with lazy subtree merging.
    fn push_chunk_cv(&mut self, cv_bytes: &[u8; 32], mut total: u64) {
        let mut merged = *cv_bytes;
        while total & 1 == 0 {
            let left = self.stack[self.stack_len - 1];
            self.stack_len -= 1;
            let mut out = [0u8; 32];
            parent_cv(&self.key, &left, &merged, self.flags, &mut out);
            merged = out;
            total >>= 1;
        }
        self.stack[self.stack_len] = merged;
        self.stack_len += 1;
    }

    /// Finish the current chunk into its chaining value (not yet merged).
    fn chunk_output_cv(&self) -> [u8; 32] {
        let words = words_from_bytes(&self.buf[..self.buf_len]);
        let mut cv = [0u32; 8];
        chaining_value(
            &self.cv,
            &words,
            self.chunk_counter,
            self.buf_len as u32,
            self.flags | self.start_flag() | CHUNK_END,
            &mut cv,
        );
        let mut bytes = [0u8; 32];
        words_to_bytes(&cv, &mut bytes);
        bytes
    }

    /// Number of bytes absorbed in the current chunk (invariant helper).
    fn chunk_len(&self) -> usize {
        let used = self.blocks_compressed as usize * BLOCK_LEN + self.buf_len;
        debug_assert!(used <= CHUNK_LEN);
        used
    }

    /// Root output state: fold the stack over the current chunk output.
    /// Left siblings (`stack[0..]`) merge oldest-first; each parent takes
    /// `key` as chaining value with `PARENT` flags.
    fn root_state(&self) -> ([u32; 8], [u32; 16], u64, u32, u32) {
        debug_assert_eq!(self.chunk_used(), self.chunk_len());
        // Output object for the current (possibly partial) chunk.
        let words = words_from_bytes(&self.buf[..self.buf_len]);
        let mut out_cv = self.cv;
        let mut out_block = words;
        let mut out_ctr = self.chunk_counter;
        let mut out_len = self.buf_len as u32;
        let mut out_flags = self.flags | self.start_flag() | CHUNK_END;
        // Fold completed left siblings oldest-first.
        let mut li = 0usize;
        while li < self.stack_len {
            let mut cv = [0u32; 8];
            chaining_value(&out_cv, &out_block, out_ctr, out_len, out_flags, &mut cv);
            let mut cvb = [0u8; 32];
            words_to_bytes(&cv, &mut cvb);
            let mut block = [0u32; 16];
            let l = words_from_32(&self.stack[li]);
            let mut i = 0usize;
            while i < 8 {
                block[i] = l[i];
                i += 1;
            }
            let r = words_from_32(&cvb);
            i = 0;
            while i < 8 {
                block[8 + i] = r[i];
                i += 1;
            }
            out_cv = self.key;
            out_block = block;
            out_ctr = 0;
            out_len = BLOCK_LEN as u32;
            out_flags = self.flags | PARENT;
            li += 1;
        }
        (out_cv, out_block, out_ctr, out_len, out_flags)
    }

    /// Finalize to exactly 32 bytes.
    #[must_use]
    pub fn finalize32(&self) -> [u8; OUT_LEN] {
        let (cv, block, ctr, len, flags) = self.root_state();
        let state = compress(&cv, &block, ctr, len, flags | ROOT);
        let mut out = [0u8; 32];
        words_to_bytes(&state[..8], &mut out);
        out
    }

    /// Squeeze arbitrary output (XOF): full 16-word blocks, counter advances.
    pub fn finalize_xof(&self, out: &mut [u8]) {
        let (cv, block, ctr0, len, flags) = self.root_state();
        let mut ctr = ctr0;
        let mut pos = 0usize;
        while pos < out.len() {
            let state = compress(&cv, &block, ctr, len, flags | ROOT);
            let mut wide = [0u8; 64];
            words_to_bytes(&state, &mut wide);
            let n = (out.len() - pos).min(64);
            out[pos..pos + n].copy_from_slice(&wide[..n]);
            ctr += 1;
            pos += n;
        }
    }
}

/// Decode 32 bytes (LE) into 8 words.
fn words_from_32(bytes: &[u8; 32]) -> [u32; 8] {
    let mut w = [0u32; 8];
    let mut i = 0usize;
    while i < 8 {
        w[i] = u32::from_le_bytes([
            bytes[4 * i],
            bytes[4 * i + 1],
            bytes[4 * i + 2],
            bytes[4 * i + 3],
        ]);
        i += 1;
    }
    w
}

impl Default for Hasher {
    fn default() -> Self {
        Self::new()
    }
}

/// Hash arbitrary input → 32 bytes.
///
/// # Example
///
/// ```rust
/// use hypg_core::b3::b3_hash;
///
/// // Official BLAKE3 vector: empty input.
/// let mut out = [0u8; 32];
/// b3_hash(b"", &mut out);
/// assert_eq!(
///     out,
///     [
///         0xaf, 0x13, 0x49, 0xb9, 0xf5, 0xf9, 0xa1, 0xa6, 0xa0, 0x40, 0x4d, 0xea, 0x36, 0xdc,
///         0xc9, 0x49, 0x9b, 0xcb, 0x25, 0xc9, 0xad, 0xc1, 0x12, 0xb7, 0xcc, 0x9a, 0x93, 0xca,
///         0xe4, 0x1f, 0x32, 0x62,
///     ]
/// );
/// ```
pub fn b3_hash(input: &[u8], out: &mut [u8; OUT_LEN]) {
    let mut h = Hasher::new();
    h.update(input);
    *out = h.finalize32();
}

/// XOF over arbitrary input.
pub fn b3_xof(out: &mut [u8], input: &[u8]) {
    let mut h = Hasher::new();
    h.update(input);
    h.finalize_xof(out);
}

/// Keyed hash → 32 bytes.
pub fn b3_keyed(key: &[u8; 32], input: &[u8], out: &mut [u8; OUT_LEN]) {
    let mut h = Hasher::new_keyed(key);
    h.update(input);
    *out = h.finalize32();
}

/// Key derivation: `derive_key(context, key_material)`.
/// Context root feeds the material root (reference construction).
pub fn b3_derive_key(context: &str, key_material: &[u8; 32], out: &mut [u8; OUT_LEN]) {
    // Context key = ROOT output of the context string under its own flags.
    let mut hc = Hasher::with_flags(DERIVE_KEY_CONTEXT);
    hc.update(context.as_bytes());
    let (cv, block, ctr, len, flags) = hc.root_state();
    let state = compress(&cv, &block, ctr, len, flags | ROOT);
    let mut ctx_key = [0u32; 8];
    ctx_key.copy_from_slice(&state[..8]);
    // Material root under the context key with MATERIAL flags.
    let mut m = Hasher {
        key: ctx_key,
        flags: DERIVE_KEY_MATERIAL,
        cv: ctx_key,
        chunk_counter: 0,
        buf: [0u8; BLOCK_LEN],
        buf_len: 0,
        blocks_compressed: 0,
        stack: [[0u8; 32]; STACK_DEPTH],
        stack_len: 0,
    };
    m.update(key_material);
    *out = m.finalize32();
    zeroize_u32(&mut ctx_key);
}

/// Expander replacing `hypg_xof`: `XOF(seed || domain)`.
pub fn b3_expand(out: &mut [u8], seed: &[u8; 32], domain: &[u8]) {
    let mut h = Hasher::new();
    h.update(seed);
    h.update(domain);
    h.finalize_xof(out);
}

/// KDF replacing `hypg_kdf`: `XOF(domain || parts...)`.
pub fn b3_kdf(out: &mut [u8], parts: &[&[u8]], domain: &[u8]) {
    let mut h = Hasher::new();
    h.update(domain);
    let mut i = 0usize;
    while i < parts.len() {
        h.update(parts[i]);
        i += 1;
    }
    h.finalize_xof(out);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hasher_debug_is_redacted() {
        let h = Hasher::new_keyed(&[0x42u8; 32]);
        let rendered = std::format!("{h:?}");
        assert_eq!(rendered, "Hasher { .. }");
        assert!(!rendered.contains("42"));
    }

    /// Parse even-length hex into `out`, returning byte length.
    fn parse_hex(s: &str, out: &mut [u8; 128]) -> usize {
        let mut n = 0usize;
        let bytes = s.as_bytes();
        let mut i = 0usize;
        while i + 1 < bytes.len() && n < 128 {
            let hi = hex_val(bytes[i]);
            let lo = hex_val(bytes[i + 1]);
            out[n] = (hi << 4) | lo;
            n += 1;
            i += 2;
        }
        n
    }

    fn hex_val(b: u8) -> u8 {
        match b {
            b'0'..=b'9' => b - b'0',
            b'a'..=b'f' => b - b'a' + 10,
            b'A'..=b'F' => b - b'A' + 10,
            _ => 0xFF,
        }
    }

    #[test]
    fn hash_empty_spec_vector() {
        // Official BLAKE3("") test vector.
        let mut out = [0u8; 32];
        b3_hash(b"", &mut out);
        let mut exp = [0u8; 128];
        let n =
            parse_hex("af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262", &mut exp);
        assert_eq!(n, 32);
        assert_eq!(&exp[..32], &out);
    }

    #[test]
    fn hash_multichunk_oracle_vectors() {
        // Captured from the official crate (`blake3 v1.8.7`).
        let v1024 = [0x5Au8; 1024];
        let v1025 = [0x5Au8; 1025];
        let v2048 = [0x5Au8; 2048];
        let v5000 = [0x5Au8; 5000];
        let cases: [(&[u8], &str); 4] = [
            (&v1024, "f6d80a7f842a8e1f8432df29fff969ea519a9a92c257ad7b2b51c7af4176ff11"),
            (&v1025, "5810d8e502b356ac15934cbeed7ae98ece5a3de5d73f5a41623417bdba4751f0"),
            (&v2048, "0620916b07ddd7d41b6ee9d1e82d3b40e336ae12dfb63e2faf70f99878755017"),
            (&v5000, "56efb8914e09145ba94e787c1ca0fea6614b3d9e5390359ef6897eabd7eadb06"),
        ];
        for (input, exp) in cases {
            let mut out = [0u8; 32];
            b3_hash(input, &mut out);
            let mut e = [0u8; 128];
            let n = parse_hex(exp, &mut e);
            assert_eq!(n, 32);
            assert_eq!(&e[..32], &out, "hash mismatch len {}", input.len());
        }
    }

    #[test]
    fn streaming_matches_oneshot() {
        // Multi-update delivery must equal one-shot (chunk-boundary + odd splits).
        let mut input = [0u8; 3000];
        let mut i = 0u32;
        while i < 3000 {
            input[i as usize] = u8::try_from(i * 7 + 3).unwrap_or(0);
            i += 1;
        }
        let mut ref_out = [0u8; 32];
        b3_hash(&input, &mut ref_out);
        for split in [0usize, 1, 63, 64, 65, 1023, 1024, 1025, 2000, 2999, 3000] {
            let mut h = Hasher::new();
            h.update(&input[..split]);
            h.update(&input[split..]);
            assert_eq!(ref_out, h.finalize32(), "streaming mismatch at split {split}");
        }
        let mut h = Hasher::new();
        h.update(&[]);
        h.update(&input[..1500]);
        h.update(&[]);
        h.update(&input[1500..]);
        assert_eq!(ref_out, h.finalize32());
    }

    #[test]
    fn keyed_oracle_vectors() {
        // Captured from the official crate (key `[0x42; 32]`, input `[0xA5; len]`).
        let key = [0x42u8; 32];
        let v0 = [0xA5u8; 0];
        let v1 = [0xA5u8; 1];
        let v64 = [0xA5u8; 64];
        let v65 = [0xA5u8; 65];
        let v1024 = [0xA5u8; 1024];
        let v1025 = [0xA5u8; 1025];
        let v2048 = [0xA5u8; 2048];
        let cases: [(&[u8], &str); 7] = [
            (&v0, "4fa213fa1c1f5ae802e09c6e384b60390a0b5a1b0f228d77d89af00a84b29a21"),
            (&v1, "e1baf3d8b3031078b59acec8224f2add7b5f3f169e5ba39388be99a4f2451e38"),
            (&v64, "90275c8065a95d1fb2d4f79f4266a45bd35e9a420d01df551026396782ff3083"),
            (&v65, "989ef1a1e9f2feac3bcb00f49b58d73cc8150ba09c59c579232ea3e530e5c2dc"),
            (&v1024, "8808def04335d47c7a9b1cea85c365c241166fe4842c41edd45916859c415454"),
            (&v1025, "15d3d0a809b9d1507e9337da823328b528fa1a16143279fbd6d8d512d19471d0"),
            (&v2048, "1338c2529d653dfff51b62c32ccafa1b46eca0f036c99c5d5ae583141a857c98"),
        ];
        for (input, exp) in cases {
            let mut out = [0u8; 32];
            b3_keyed(&key, input, &mut out);
            let mut e = [0u8; 128];
            let n = parse_hex(exp, &mut e);
            assert_eq!(n, 32);
            assert_eq!(&e[..32], &out, "keyed mismatch len {}", input.len());
        }
    }

    #[test]
    fn derive_oracle_vectors() {
        let km = [0x11u8; 32];
        for (ctx, exp) in [
            (
                "HypG/v07/symm-enc",
                "0b9dcac2f12bcded83971230418e06c2f4f207bdeb439b819bf2c4380db92fd3",
            ),
            (
                "HypG/v07/symm-mac",
                "97da8ccb5417dd90d29938265dd5bc02f808e5b27caff7b700053c4bcd6b6489",
            ),
        ] {
            let mut out = [0u8; 32];
            b3_derive_key(ctx, &km, &mut out);
            let mut e = [0u8; 128];
            let n = parse_hex(exp, &mut e);
            assert_eq!(n, 32);
            assert_eq!(&e[..32], &out, "derive mismatch {ctx}");
        }
    }

    #[test]
    fn xof_oracle_vectors() {
        // "hello xof world" outputs captured from the official crate.
        for (len, exp) in [
            (32usize, "159178064be9518ba5c589cefe79fcf2c2e62ffb0134fa6e312db5ca87de7163"),
            (64usize, "159178064be9518ba5c589cefe79fcf2c2e62ffb0134fa6e312db5ca87de716330dd781293784444274af3de2de5f9db1833f7da144f573c10d01e9e4f89b75a"),
            (
                100usize,
                "159178064be9518ba5c589cefe79fcf2c2e62ffb0134fa6e312db5ca87de716330dd781293784444274af3de2de5f9db1833f7da144f573c10d01e9e4f89b75a168f48c8330471a52e9ac6cde1d7a521e557f0b96e76297d73a2721ce2257f8363f4bc90",
            ),
            (
                128usize,
                "159178064be9518ba5c589cefe79fcf2c2e62ffb0134fa6e312db5ca87de716330dd781293784444274af3de2de5f9db1833f7da144f573c10d01e9e4f89b75a168f48c8330471a52e9ac6cde1d7a521e557f0b96e76297d73a2721ce2257f8363f4bc907289cf97c1f1541e118efdddafb0df65de5dc90a100e15aee4742379",
            ),
        ] {
            let mut out = [0u8; 128];
            b3_xof(&mut out[..len], b"hello xof world");
            let mut e = [0u8; 128];
            let n = parse_hex(exp, &mut e);
            assert_eq!(n, len);
            assert_eq!(&e[..len], &out[..len], "xof mismatch at len {len}");
        }
    }

    #[test]
    fn xof_multiblock_input_oracle_vectors() {
        // Multi-chunk inputs captured from the official crate.
        let v200 = [0xA5u8; 200];
        let v2000 = [0xA5u8; 2000];
        for (input, olen, exp) in [
            (
                &v200[..],
                32usize,
                "52d5f801e49589f36779845e5c75792d43c892c4c94caf32d117af9c4a9495ea",
            ),
            (
                &v2000[..],
                100usize,
                "0c625ab643364a99e26657ad06231132d5e73ee556f68d40110331083f372d50522c7b81278089891e25227011d23fc0da8be603fcea8a5937948d897f78fd839cbbcaa705da3a2b02bd1dcb022037cb269cce37ed65da0bb063f183b54c91ac90dab799",
            ),
        ] {
            let mut out = [0u8; 128];
            b3_xof(&mut out[..olen], input);
            let mut e = [0u8; 128];
            let n = parse_hex(exp, &mut e);
            assert_eq!(n, olen);
            assert_eq!(&e[..olen], &out[..olen], "xof-in mismatch");
        }
    }

    #[test]
    fn expand_kdf_shapes() {
        // Compat-shape helpers: determinism + domain separation + sizes.
        let seed = [0x77u8; 32];
        let mut a = [0u8; 96];
        let mut b = [0u8; 96];
        b3_expand(&mut a, &seed, b"dom-a");
        b3_expand(&mut b, &seed, b"dom-a");
        assert_eq!(a, b);
        b3_expand(&mut b, &seed, b"dom-b");
        assert_ne!(a, b);
        let mut k1 = [0u8; 64];
        let mut k2 = [0u8; 64];
        b3_kdf(&mut k1, &[b"one", b"two"], b"d1");
        b3_kdf(&mut k2, &[b"one", b"two"], b"d1");
        assert_eq!(k1, k2);
        b3_kdf(&mut k2, &[b"one", b"two"], b"d2");
        assert_ne!(k1, k2);
    }
}
