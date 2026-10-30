//! Module-LWE polynomial layer: `R_q = Z_q[X]/(X^256+1)`, `q = 2^12`.
//!
//! All operations are branchless w.r.t. secrets: fixed public loop bounds,
//! no secret branches or indices, power-of-two moduli (mask/shift only,
//! no division). `no_std`, zero-dep.
//!
//! Intentional `as` casts: all truncations are immediately masked to the
//! modulus bit-width and all sign conversions feed that mask (correct mod
//! `2^k` for two's complement, branchless, no panic paths).

#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss,
    clippy::cast_lossless
)]

use crate::ct::zeroize_u16;
use crate::params::{
    C1_PACKED_LEN, C1_Q_MASK, C2_PACKED_LEN, C2_Q_MASK, CBD_ETA, CBD_RAND_LEN, ENCODE_SHIFT,
    MOD_Q_MASK, MSG_LEN, POLY_N, POLY_PACKED_LEN,
};

/// Polynomial with coefficients in `0..4096` (always reduced).
///
/// Coefficients may be secret (`s`, `e`, `r`), so `Debug` is redacted and
/// equality scans the full coefficient vector (no early exit).
#[derive(Clone, Copy)]
pub struct Poly(pub [u16; POLY_N]);

impl core::fmt::Debug for Poly {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Poly { .. }")
    }
}

impl PartialEq for Poly {
    fn eq(&self, other: &Self) -> bool {
        let mut diff = 0u16;
        let mut i = 0usize;
        while i < POLY_N {
            diff |= self.0[i] ^ other.0[i];
            i += 1;
        }
        diff == 0
    }
}
impl Eq for Poly {}

impl Poly {
    /// Zero polynomial.
    #[must_use]
    pub const fn zero() -> Self {
        Self([0u16; POLY_N])
    }

    /// Element-wise add mod `q` (mask reduction).
    #[must_use]
    pub fn add(&self, other: &Self) -> Self {
        let mut out = [0u16; POLY_N];
        let mut i = 0usize;
        while i < POLY_N {
            out[i] = self.0[i].wrapping_add(other.0[i]) & MOD_Q_MASK;
            i += 1;
        }
        Self(out)
    }

    /// Element-wise sub mod `q`.
    #[must_use]
    pub fn sub(&self, other: &Self) -> Self {
        let mut out = [0u16; POLY_N];
        let mut i = 0usize;
        while i < POLY_N {
            out[i] = self.0[i].wrapping_sub(other.0[i]) & MOD_Q_MASK;
            i += 1;
        }
        Self(out)
    }

    /// Negacyclic multiply mod `X^n+1`, mod `q` (`n = 256`, naive `O(n^2)`).
    ///
    /// `c[k] = sum_{i+j=k} a[i]b[j] - sum_{i+j=k+n} a[i]b[j] (mod q)`.
    /// `i64` accumulator (max `256·4095² ≈ 4.3e9`, fits with margin);
    /// final mod is a low-12-bit mask (correct for two's-complement
    /// negatives since `q = 2^12`). Loop conditions on public indices only.
    #[must_use]
    #[allow(clippy::many_single_char_names)]
    pub fn mul(&self, other: &Self) -> Self {
        let mut out = [0u16; POLY_N];
        let mut k = 0usize;
        while k < POLY_N {
            let mut acc: i64 = 0;
            let mut i = 0usize;
            while i < POLY_N {
                let jdx: usize = if i <= k { k - i } else { k + POLY_N - i };
                let prod = (self.0[i] as i64) * (other.0[jdx] as i64);
                if i <= k {
                    acc += prod;
                } else {
                    acc -= prod;
                }
                i += 1;
            }
            // `if` above is on PUBLIC indices (`i`, `k`), never secrets.
            out[k] = ((acc as u64) & (MOD_Q_MASK as u64)) as u16;
            k += 1;
        }
        Self(out)
    }

    /// Inner product of two length-`k` vectors is provided as a free
    /// function below (`dot`); this helper adds two polys (alias).
    #[must_use]
    pub fn add_assign_sum(&self, other: &Self) -> Self {
        self.add(other)
    }

    /// Encode 32-byte message, 1 bit per coefficient:
    /// `coeff = bit << 11` (spacing `q/2 = 2048`).
    #[must_use]
    pub fn encode(msg: &[u8; MSG_LEN]) -> Self {
        let mut out = [0u16; POLY_N];
        let mut i = 0usize;
        while i < POLY_N {
            let bit = ((msg[i / 8] >> (i % 8)) & 1) as u16;
            out[i] = bit << ENCODE_SHIFT;
            i += 1;
        }
        Self(out)
    }

    /// Decode by rounding to nearest of `{0, 2048}` mod `q`:
    /// `bit = (((v + 1024) mod q) >> 11) & 1`. Wrap-correct.
    #[must_use]
    pub fn decode(&self) -> [u8; MSG_LEN] {
        let mut msg = [0u8; MSG_LEN];
        let mut i = 0usize;
        while i < POLY_N {
            let v = self.0[i] & MOD_Q_MASK;
            let bit = ((((v as u32) + 1024) & (MOD_Q_MASK as u32)) >> ENCODE_SHIFT) as u8 & 1;
            msg[i / 8] |= bit << (i % 8);
            i += 1;
        }
        msg
    }

    /// Compress `12 -> 10` bits with rounding: `((c + 2) >> 2) & 0x3FF`.
    #[must_use]
    pub fn compress10(&self) -> Poly10 {
        let mut out = [0u16; POLY_N];
        let mut i = 0usize;
        while i < POLY_N {
            out[i] = (((self.0[i] as u32) + 2) >> 2) as u16 & C1_Q_MASK;
            i += 1;
        }
        Poly10(out)
    }

    /// Compress `12 -> 5` bits with rounding: `((c + 64) >> 7) & 0x1F`.
    #[must_use]
    pub fn compress5(&self) -> Poly5 {
        let mut out = [0u16; POLY_N];
        let mut i = 0usize;
        while i < POLY_N {
            out[i] = (((self.0[i] as u32) + 64) >> 7) as u16 & C2_Q_MASK;
            i += 1;
        }
        Poly5(out)
    }

    /// Pack 12-bit coefficients into 384 bytes (2 coeffs / 3 bytes).
    #[must_use]
    pub fn pack12(&self) -> [u8; POLY_PACKED_LEN] {
        let mut out = [0u8; POLY_PACKED_LEN];
        let mut i = 0usize;
        while i < POLY_N / 2 {
            let c0 = self.0[2 * i] & MOD_Q_MASK;
            let c1 = self.0[2 * i + 1] & MOD_Q_MASK;
            out[3 * i] = (c0 & 0xFF) as u8;
            out[3 * i + 1] = (((c0 >> 8) & 0x0F) | ((c1 & 0x0F) << 4)) as u8;
            out[3 * i + 2] = ((c1 >> 4) & 0xFF) as u8;
            i += 1;
        }
        out
    }

    /// Unpack 384 bytes into 12-bit coefficients.
    #[must_use]
    pub fn unpack12(bytes: &[u8; POLY_PACKED_LEN]) -> Self {
        let mut out = [0u16; POLY_N];
        let mut i = 0usize;
        while i < POLY_N / 2 {
            let b0 = bytes[3 * i] as u16;
            let b1 = bytes[3 * i + 1] as u16;
            let b2 = bytes[3 * i + 2] as u16;
            out[2 * i] = (b0 | ((b1 & 0x0F) << 8)) & MOD_Q_MASK;
            out[2 * i + 1] = (((b1 >> 4) & 0x0F) | (b2 << 4)) & MOD_Q_MASK;
            i += 1;
        }
        Self(out)
    }
}

/// Inner product `a·b = sum_i a[i]*b[i]` over `R_q`. The loop bound is
/// public (module rank) and the function is total: on unequal lengths it
/// consumes the common prefix instead of panicking.
#[must_use]
pub fn dot(a: &[Poly], b: &[Poly]) -> Poly {
    let n = if a.len() < b.len() { a.len() } else { b.len() };
    let mut acc = Poly::zero();
    let mut i = 0usize;
    while i < n {
        let mut prod = a[i].mul(&b[i]);
        acc = acc.add(&prod);
        zeroize_u16(&mut prod.0);
        i += 1;
    }
    acc
}

/// Fixed two-term inner product, retained for compatibility with the
/// v1.x test harnesses. New code should use [`dot`].
#[must_use]
pub fn dot2(a0: &Poly, a1: &Poly, b0: &Poly, b1: &Poly) -> Poly {
    let mut p0 = a0.mul(b0);
    let mut p1 = a1.mul(b1);
    let out = p0.add(&p1);
    zeroize_u16(&mut p0.0);
    zeroize_u16(&mut p1.0);
    out
}

/// Polynomial with 10-bit coefficients (compressed `c1`).
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Poly10(pub [u16; POLY_N]);

impl core::fmt::Debug for Poly10 {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Poly10 { .. }")
    }
}

impl Poly10 {
    /// Decompress `10 -> 12` bits: `c << 2`.
    #[must_use]
    pub fn decompress(&self) -> Poly {
        let mut out = [0u16; POLY_N];
        let mut i = 0usize;
        while i < POLY_N {
            out[i] = (self.0[i] & C1_Q_MASK) << 2;
            i += 1;
        }
        Poly(out)
    }

    /// Pack 10-bit coefficients into 320 bytes via bit-stream.
    #[must_use]
    pub fn pack10(&self) -> [u8; C1_PACKED_LEN] {
        pack_bits(&self.0, 10)
    }

    /// Unpack 320 bytes into 10-bit coefficients.
    #[must_use]
    pub fn unpack10(bytes: &[u8; C1_PACKED_LEN]) -> Self {
        Self(unpack_bits(bytes, 10))
    }
}

/// Polynomial with 5-bit coefficients (compressed `c2`).
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Poly5(pub [u16; POLY_N]);

impl core::fmt::Debug for Poly5 {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Poly5 { .. }")
    }
}

impl Poly5 {
    /// Decompress `5 -> 12` bits: `c << 7`.
    #[must_use]
    pub fn decompress(&self) -> Poly {
        let mut out = [0u16; POLY_N];
        let mut i = 0usize;
        while i < POLY_N {
            out[i] = (self.0[i] & C2_Q_MASK) << 7;
            i += 1;
        }
        Poly(out)
    }

    /// Pack 5-bit coefficients into 160 bytes via bit-stream.
    #[must_use]
    pub fn pack5(&self) -> [u8; C2_PACKED_LEN] {
        pack_bits(&self.0, 5)
    }

    /// Unpack 160 bytes into 5-bit coefficients.
    #[must_use]
    pub fn unpack5(bytes: &[u8; C2_PACKED_LEN]) -> Self {
        Self(unpack_bits(bytes, 5))
    }
}

/// Generic bit-stream packer: `POLY_N` coefficients of `bits` width.
/// `bits` is always a public constant (10 or 5) at call sites.
fn pack_bits<const OUT: usize>(coeffs: &[u16; POLY_N], bits: u32) -> [u8; OUT] {
    let mut out = [0u8; OUT];
    let mask = if bits >= 16 { 0xFFFF } else { (1u32 << bits) - 1 };
    let mut acc: u32 = 0;
    let mut acc_bits: u32 = 0;
    let mut pos = 0usize;
    let mut i = 0usize;
    while i < POLY_N {
        acc |= ((coeffs[i] as u32) & mask) << acc_bits;
        acc_bits += bits;
        while acc_bits >= 8 {
            out[pos] = (acc & 0xFF) as u8;
            pos += 1;
            acc >>= 8;
            acc_bits -= 8;
        }
        i += 1;
    }
    debug_assert!(pos == OUT && acc_bits == 0);
    out
}

/// Generic bit-stream unpacker.
fn unpack_bits<const INP: usize>(bytes: &[u8; INP], bits: u32) -> [u16; POLY_N] {
    let mut out = [0u16; POLY_N];
    let mask = if bits >= 16 { 0xFFFF } else { (1u32 << bits) - 1 };
    let mut acc: u32 = 0;
    let mut acc_bits: u32 = 0;
    let mut pos = 0usize;
    let mut i = 0usize;
    while i < POLY_N {
        while acc_bits < bits {
            acc |= (bytes[pos] as u32) << acc_bits;
            pos += 1;
            acc_bits += 8;
        }
        out[i] = (acc & mask) as u16;
        acc >>= bits;
        acc_bits -= bits;
        i += 1;
    }
    out
}

/// Centered binomial `CBD(eta=2)`: 4 random bits per coefficient,
/// `(b0+b1)-(b2+b3)` in `-2..=2`, mapped mod `q`.
///
/// Takes 128 uniformly random bytes (`256 coeffs × 4 bits`).
/// Branchless: sums and mask only.
#[must_use]
pub fn cbd_eta2(rand128: &[u8; CBD_RAND_LEN]) -> Poly {
    // Underscore-const form (not inline-`const`) so the MSRV 1.70
    // toolchain accepts this compile-time parameter check.
    const _: () = assert!(CBD_ETA == 2);
    let mut out = [0u16; POLY_N];
    let mut i = 0usize;
    while i < POLY_N {
        let bit_pos = i * 4;
        let b0 = ((rand128[bit_pos / 8] >> (bit_pos % 8)) & 1) as i16;
        let b1 = ((rand128[(bit_pos + 1) / 8] >> ((bit_pos + 1) % 8)) & 1) as i16;
        let b2 = ((rand128[(bit_pos + 2) / 8] >> ((bit_pos + 2) % 8)) & 1) as i16;
        let b3 = ((rand128[(bit_pos + 3) / 8] >> ((bit_pos + 3) % 8)) & 1) as i16;
        let v: i16 = (b0 + b1) - (b2 + b3);
        out[i] = ((v as i32 + MOD_Q_MASK as i32 + 1) as u16) & MOD_Q_MASK;
        i += 1;
    }
    Poly(out)
}

/// Uniform polynomial from 384 pseudorandom bytes (12 bits/coeff).
#[must_use]
pub fn uniform_from_packed(rand384: &[u8; POLY_PACKED_LEN]) -> Poly {
    Poly::unpack12(rand384)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dot_is_total_on_unequal_lengths() {
        let a = [Poly::zero(); 3];
        let b = [Poly::zero(); 2];
        assert_eq!(dot(&a, &b), Poly::zero());
        assert_eq!(dot(&b, &a), Poly::zero());
        assert_eq!(dot(&[], &a), Poly::zero());
    }

    #[test]
    fn poly_debug_is_redacted() {
        let p = Poly([7u16; POLY_N]);
        assert_eq!(std::format!("{p:?}"), "Poly { .. }");
        assert!(!std::format!("{p:?}").contains('7'));
    }

    #[test]
    fn pack12_round_trip() {
        let mut coeffs = [0u16; POLY_N];
        let mut i = 0usize;
        while i < POLY_N {
            coeffs[i] = ((i * 63 + 7) & (MOD_Q_MASK as usize)) as u16;
            i += 1;
        }
        let p = Poly(coeffs);
        let packed = p.pack12();
        assert_eq!(packed.len(), POLY_PACKED_LEN);
        assert_eq!(Poly::unpack12(&packed), p);
    }

    #[test]
    fn pack10_round_trip() {
        let mut coeffs = [0u16; POLY_N];
        let mut i = 0usize;
        while i < POLY_N {
            coeffs[i] = ((i * 17 + 3) & (C1_Q_MASK as usize)) as u16;
            i += 1;
        }
        let p = Poly10(coeffs);
        let packed = p.pack10();
        assert_eq!(packed.len(), C1_PACKED_LEN);
        assert_eq!(Poly10::unpack10(&packed), p);
    }

    #[test]
    fn pack5_round_trip() {
        let mut coeffs = [0u16; POLY_N];
        let mut i = 0usize;
        while i < POLY_N {
            coeffs[i] = ((i * 7 + 1) & (C2_Q_MASK as usize)) as u16;
            i += 1;
        }
        let p = Poly5(coeffs);
        let packed = p.pack5();
        assert_eq!(packed.len(), C2_PACKED_LEN);
        assert_eq!(Poly5::unpack5(&packed), p);
    }

    #[test]
    fn encode_decode_clean() {
        let msg = [0xA5u8; 32];
        assert_eq!(Poly::encode(&msg).decode(), msg);
        let mut seq = [0u8; 32];
        let mut i = 0u32;
        while i < 32 {
            seq[i as usize] = u8::try_from(i * 7 + 3).unwrap_or(0);
            i += 1;
        }
        assert_eq!(Poly::encode(&seq).decode(), seq);
    }

    #[test]
    fn cbd_zero_on_uniform_bits() {
        let r = [0xFFu8; CBD_RAND_LEN];
        for c in cbd_eta2(&r).0 {
            assert_eq!(c, 0);
        }
        let z = [0x00u8; CBD_RAND_LEN];
        for c in cbd_eta2(&z).0 {
            assert_eq!(c, 0);
        }
    }

    #[test]
    fn mul_identity() {
        let mut one = [0u16; POLY_N];
        one[0] = 1;
        let a = Poly(one);
        let mut bvals = [0u16; POLY_N];
        let mut i = 0usize;
        while i < POLY_N {
            bvals[i] = ((i * 11) & (MOD_Q_MASK as usize)) as u16;
            i += 1;
        }
        let b = Poly(bvals);
        assert_eq!(a.mul(&b), b);
        assert_eq!(b.mul(&a), b);
    }

    #[test]
    fn mul_negacyclic_wrap() {
        // `X^255 * X = X^256 = -1` in `X^256+1`.
        let mut xlast = [0u16; POLY_N];
        xlast[POLY_N - 1] = 1;
        let mut x1 = [0u16; POLY_N];
        x1[1] = 1;
        let r = Poly(xlast).mul(&Poly(x1));
        assert_eq!(r.0[0], MOD_Q_MASK); // `-1 mod q`
        for k in 1..POLY_N {
            assert_eq!(r.0[k], 0);
        }
    }

    #[test]
    fn mul_commutative_and_associative() {
        // Negacyclic convolution is ordinary polynomial multiplication
        // mod `X^256+1`: commutativity + associativity hold exactly.
        let mk = |a: u32, b: u32| {
            let mut v = [0u16; POLY_N];
            let mut i = 0u32;
            while (i as usize) < POLY_N {
                v[i as usize] =
                    u16::try_from(i.wrapping_mul(a).wrapping_add(b) & 0xFFF).unwrap_or(0);
                i += 1;
            }
            Poly(v)
        };
        let (x, y, z) = (mk(11, 7), mk(37, 1), mk(101, 3));
        assert_eq!(x.mul(&y), y.mul(&x), "commutativity");
        assert_eq!(x.mul(&y).mul(&z), x.mul(&y.mul(&z)), "associativity");
    }

    #[test]
    fn decode_noise_margin() {
        // 1-bit encode: spacing 2048, threshold ±1024. Errors up to ±1023
        // must not flip; ±1024 sits exactly on the boundary (adversarial
        // tie — assert the tie goes to a *stable* value, not which one).
        let msg_one = [0xFFu8; 32]; // bit 1 -> coeff 2048
        let base = Poly::encode(&msg_one);
        for c in base.0 {
            assert_eq!(c, 2048);
        }
        // +1023 stays 1.
        let mut noisy = base;
        for c in &mut noisy.0 {
            *c = c.wrapping_add(1023) & MOD_Q_MASK;
        }
        assert_eq!(noisy.decode(), msg_one);
        // -1023 stays 1.
        let mut noisy = base;
        for c in &mut noisy.0 {
            *c = c.wrapping_sub(1023) & MOD_Q_MASK;
        }
        assert_eq!(noisy.decode(), msg_one);
        // Bit 0 with wrap-around noise (-1 mod q) stays 0.
        let msg_zero = [0x00u8; 32];
        let base0 = Poly::encode(&msg_zero);
        let mut wrap = base0;
        for c in &mut wrap.0 {
            *c = c.wrapping_sub(1) & MOD_Q_MASK; // 4095 = -1
        }
        assert_eq!(wrap.decode(), msg_zero);
        // Compression round-trips preserve the message: 12->10->12 and
        // 12->5->12 errors (max ±2 and ±64) sit far inside ±1024.
        assert_eq!(base.compress10().decompress().decode(), msg_one);
        assert_eq!(base.compress5().decompress().decode(), msg_one);
        assert_eq!(base0.compress10().decompress().decode(), msg_zero);
        assert_eq!(base0.compress5().decompress().decode(), msg_zero);
    }

    #[test]
    fn pack12_extremes() {
        // All-zero and all-max (`0xFFF`) polynomials must round-trip.
        assert_eq!(Poly::unpack12(&Poly::zero().pack12()), Poly::zero());
        let max = Poly([MOD_Q_MASK; POLY_N]);
        assert_eq!(Poly::unpack12(&max.pack12()), max);
    }

    #[test]
    fn cbd_range_and_signs() {
        // `0xAA` bit pattern -> per-coeff bits (0,1,0,1): (0+1)-(0+1) = 0.
        // `0x96` = 0b10010110 -> bits (0,1,1,0),(0,1,1,0)...: (0+1)-(1+0) = 0.
        // Exhaustive single-poly check over all 256 4-bit nibble values
        // is overkill; instead verify range over pseudo-random stream and
        // that both signs occur (attacker-visible bias would break LWE).
        let mut stream = [0u8; CBD_RAND_LEN];
        let mut i = 0u32;
        while i < CBD_RAND_LEN as u32 {
            stream[i as usize] = (i.wrapping_mul(0x9E37_79B9).wrapping_add(0x85EB_CA6B)) as u8;
            i += 1;
        }
        let p = cbd_eta2(&stream);
        let mut neg = false;
        let mut pos = false;
        for c in p.0 {
            // Reduced value must decode back to -2..=2.
            let signed =
                if c > MOD_Q_MASK / 2 { (c as i32) - (MOD_Q_MASK as i32) - 1 } else { c as i32 };
            assert!((-2..=2).contains(&signed), "CBD out of range: {c}");
            if signed < 0 {
                neg = true;
            }
            if signed > 0 {
                pos = true;
            }
        }
        assert!(neg && pos, "CBD stream produced no sign variation");
    }
}
