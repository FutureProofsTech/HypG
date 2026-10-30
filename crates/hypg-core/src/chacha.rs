//! `ChaCha20` stream cipher (RFC 8439 §2, IETF 12-byte nonce).
//!
//! `no_std`, zero-dependency, `forbid(unsafe_code)`. Scalar only.
//! Used by `hypg-symm` for encryption (authentication comes from
//! keyed BLAKE3 — Encrypt-then-MAC, each primitive as designed).
//! Test vectors captured from the reference `chacha20 v0.9.1` crate
//! (provenance in commit history).

use crate::ct::{zeroize, zeroize_u32};

#[allow(clippy::many_single_char_names)]
fn quarter_round(s: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
    s[a] = s[a].wrapping_add(s[b]);
    s[d] ^= s[a];
    s[d] = s[d].rotate_left(16);
    s[c] = s[c].wrapping_add(s[d]);
    s[b] ^= s[c];
    s[b] = s[b].rotate_left(12);
    s[a] = s[a].wrapping_add(s[b]);
    s[d] ^= s[a];
    s[d] = s[d].rotate_left(8);
    s[c] = s[c].wrapping_add(s[d]);
    s[b] ^= s[c];
    s[b] = s[b].rotate_left(7);
}

/// One 64-byte keystream block for `(key, nonce, counter)`.
/// Public for streaming consumers (`hypg-aead` buffers partial blocks
/// across `update` calls); prefer [`xor_in_place`] for one-shot use.
#[allow(clippy::many_single_char_names)]
pub fn block(key: &[u8; 32], nonce: &[u8; 12], counter: u32, out: &mut [u8; 64]) {
    let mut s = [
        0x6170_7865u32,
        0x3320_646eu32,
        0x7962_2d32u32,
        0x6b20_6574u32,
        u32::from_le_bytes([key[0], key[1], key[2], key[3]]),
        u32::from_le_bytes([key[4], key[5], key[6], key[7]]),
        u32::from_le_bytes([key[8], key[9], key[10], key[11]]),
        u32::from_le_bytes([key[12], key[13], key[14], key[15]]),
        u32::from_le_bytes([key[16], key[17], key[18], key[19]]),
        u32::from_le_bytes([key[20], key[21], key[22], key[23]]),
        u32::from_le_bytes([key[24], key[25], key[26], key[27]]),
        u32::from_le_bytes([key[28], key[29], key[30], key[31]]),
        counter,
        u32::from_le_bytes([nonce[0], nonce[1], nonce[2], nonce[3]]),
        u32::from_le_bytes([nonce[4], nonce[5], nonce[6], nonce[7]]),
        u32::from_le_bytes([nonce[8], nonce[9], nonce[10], nonce[11]]),
    ];
    let mut initial = s;
    let mut r = 0usize;
    while r < 10 {
        quarter_round(&mut s, 0, 4, 8, 12);
        quarter_round(&mut s, 1, 5, 9, 13);
        quarter_round(&mut s, 2, 6, 10, 14);
        quarter_round(&mut s, 3, 7, 11, 15);
        quarter_round(&mut s, 0, 5, 10, 15);
        quarter_round(&mut s, 1, 6, 11, 12);
        quarter_round(&mut s, 2, 7, 8, 13);
        quarter_round(&mut s, 3, 4, 9, 14);
        r += 1;
    }
    let mut i = 0usize;
    while i < 16 {
        let w = s[i].wrapping_add(initial[i]).to_le_bytes();
        let mut k = 0usize;
        while k < 4 {
            out[4 * i + k] = w[k];
            k += 1;
        }
        i += 1;
    }
    zeroize_u32(&mut s);
    zeroize_u32(&mut initial);
}

/// XOR `buf` with the keystream from `ctr0` upward (in place).
/// Returns bytes processed; stops before the 32-bit counter wraps, so a
/// short return means the message exceeded the 256 GiB block space.
/// (Callers enforce length limits; lengths are public.)
#[must_use]
pub fn xor_in_place(key: &[u8; 32], nonce: &[u8; 12], ctr0: u32, buf: &mut [u8]) -> usize {
    let mut counter = ctr0;
    let mut done = 0usize;
    while done < buf.len() {
        let mut blk = [0u8; 64];
        block(key, nonce, counter, &mut blk);
        // The 2³²nd block is usable; anything beyond would wrap.
        let last = counter.checked_add(1).is_none();
        let n = (buf.len() - done).min(64);
        let mut i = 0usize;
        while i < n {
            buf[done + i] ^= blk[i];
            i += 1;
        }
        zeroize(&mut blk);
        done += n;
        if last {
            break;
        }
        counter += 1;
    }
    done
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Parse even-length hex into `out`, returning byte length.
    fn parse_hex(s: &str, out: &mut [u8; 256]) -> usize {
        let bytes = s.as_bytes();
        let mut n = 0usize;
        let mut i = 0usize;
        while i + 1 < bytes.len() && n < 256 {
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

    /// Parse expected hex and compare against `got` (fixed buffers, no alloc).
    fn assert_eq_chacha(exp_hex: &str, got: &[u8]) {
        let mut exp = [0u8; 256];
        let n = parse_hex(exp_hex, &mut exp);
        assert_eq!(n, got.len(), "length mismatch");
        assert_eq!(&exp[..n], got);
    }

    fn seq_key() -> [u8; 32] {
        let mut key = [0u8; 32];
        let mut i = 0u32;
        while i < 32 {
            key[i as usize] = u8::try_from(i).unwrap_or(0xFF);
            i += 1;
        }
        key
    }

    fn seq_nonce() -> [u8; 12] {
        let mut nonce = [0u8; 12];
        let mut i = 0u32;
        while i < 12 {
            nonce[i as usize] = u8::try_from(i * 7 + 3).unwrap_or(0xFF);
            i += 1;
        }
        nonce
    }

    #[test]
    fn keystream_zero() {
        let mut out = [0u8; 64];
        block(&[0u8; 32], &[0u8; 12], 0, &mut out);
        assert_eq_chacha(
            "76b8e0ada0f13d90405d6ae55386bd28bdd219b8a08ded1aa836efcc8b770dc7da41597c5157488d7724e03fb8d84a376a43b8f41518a11cc387b669b2ee6586",
            &out
        );
    }

    #[test]
    fn keystream_zero_ctr1() {
        let mut out = [0u8; 64];
        block(&[0u8; 32], &[0u8; 12], 1, &mut out);
        assert_eq_chacha(
            "9f07e7be5551387a98ba977c732d080dcb0f29a048e3656912c6533e32ee7aed29b721769ce64e43d57133b074d839d531ed1f28510afb45ace10a1f4b794d6f",
            &out
        );
    }

    #[test]
    fn keystream_seq() {
        let mut out = [0u8; 64];
        block(&seq_key(), &seq_nonce(), 0, &mut out);
        assert_eq_chacha(
            "4857ffecd4436e33b12e253f5c029c7544bd480c5828bff43a4e4c9820b4690e521080b588f0f73d20aefc188cda7baac447f021cad3cde2b8c43e09e39ace46",
            &out
        );
    }

    #[test]
    fn keystream_ff() {
        let mut out = [0u8; 64];
        block(&[0xFFu8; 32], &[0xFFu8; 12], 0xFFFF_FFFE, &mut out);
        assert_eq_chacha(
            "7e5709961e09fccd84e36881e70abfd09e4f8c9cc9644c73dd5715cebf3c25e04925ea9f3eadd4532017b67842867d0824996dec95d758c2b2645013e23e8fca",
            &out
        );
    }

    #[test]
    fn encrypt_200_matches_oracle() {
        let mut buf = [0xABu8; 200];
        let done = xor_in_place(&seq_key(), &[9u8; 12], 0, &mut buf);
        assert_eq!(done, 200);
        assert_eq_chacha(
            "d12b3d62fc6dada72569a183ab39391fbf50e728c7e2a397ad95b5463a2c1449f792cc92b8cb6d14f83a2199b9cfea87b4884321bfe561cdbb908ace5d13dff19ad420058155c3a0747ea067b053185b23eb3f7d0289b6c405a99534ce1683bb6e2503486d54fa7087aebc637953972314c84b28c288c8d0c8fe767f96e85047563265a7e244a02f2344cac7648a5c7318e3e0ca91c5facea743500501691ecb041458c06c4fe967ca9839935a355b475f632c92e961a74f96648ad7dbb1cf752ed5809913610a29",
            &buf
        );
    }

    #[test]
    fn xor_is_involution_and_counter_steps() {
        let key = [0x42u8; 32];
        let nonce = [0x11u8; 12];
        let mut buf = [0xA5u8; 200];
        let orig = buf;
        assert_eq!(xor_in_place(&key, &nonce, 0, &mut buf), 200);
        assert_ne!(buf, orig);
        assert_eq!(xor_in_place(&key, &nonce, 0, &mut buf), 200);
        assert_eq!(buf, orig);
        let mut buf2 = [0xA5u8; 200];
        assert_eq!(xor_in_place(&key, &nonce, 1, &mut buf2), 200);
        assert_ne!(buf2, orig);
    }

    #[test]
    fn counter_exhaustion_stops_cleanly() {
        let key = seq_key();
        let nonce = seq_nonce();
        // Two blocks before the 32-bit wrap over a 200-byte buffer:
        // exactly 128 bytes are processable; the tail stays untouched
        // and the counter never wraps.
        let mut buf = [0xAAu8; 200];
        let orig = buf;
        assert_eq!(xor_in_place(&key, &nonce, 0xFFFF_FFFE, &mut buf), 128);
        assert_eq!(&buf[128..], &orig[128..], "tail must stay untouched");
        assert_ne!(&buf[..128], &orig[..128]);
        // Processed prefix equals two single-block applications.
        let mut expect = [0xAAu8; 128];
        let mut c = 0xFFFF_FFFEu32;
        let mut o = 0usize;
        while o < 128 {
            let mut blk = [0u8; 64];
            block(&key, &nonce, c, &mut blk);
            let mut i = 0usize;
            while i < 64 {
                expect[o + i] ^= blk[i];
                i += 1;
            }
            o += 64;
            c = c.wrapping_add(1);
        }
        assert_eq!(&buf[..128], &expect);
        // Involution on the processed part restores it.
        assert_eq!(xor_in_place(&key, &nonce, 0xFFFF_FFFE, &mut buf[..128]), 128);
        assert_eq!(&buf[..128], &orig[..128]);
        // Starting at `u32::MAX`: exactly one block, then stop.
        let mut one = [0xBBu8; 65];
        assert_eq!(xor_in_place(&key, &nonce, u32::MAX, &mut one), 64);
        assert_eq!(one[64], 0xBB);
    }
}
