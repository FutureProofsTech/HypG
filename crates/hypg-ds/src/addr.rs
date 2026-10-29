//! `ADRS`: 32-byte tweak structure (LE fields, all public).
//!
//! Layout: `layer[0..4] | tree[4..16] | type[16..20] | fields[20..32]`.
//! Types: `0` FORS, `1` WOTS-HASH, `2` WOTS-PK, `3` TREE, `4` ROOT.

use crate::params::N;

/// Address bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Addr(pub [u8; N]);

/// Address types (normative).
pub const T_FORS: u32 = 0;
/// WOTS+ chain hashing.
pub const T_WOTS_HASH: u32 = 1;
/// WOTS+ public-key compression (L-tree).
pub const T_WOTS_PK: u32 = 2;
/// Merkle tree node hashing.
pub const T_TREE: u32 = 3;
/// Hypertree root compression.
pub const T_ROOT: u32 = 4;

impl Addr {
    /// Zero address.
    #[must_use]
    pub const fn zero() -> Self {
        Self([0u8; N])
    }

    /// Raw bytes (for hash input).
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; N] {
        &self.0
    }

    fn set_u32(&mut self, at: usize, v: u32) {
        let le = v.to_le_bytes();
        let mut i = 0usize;
        while i < 4 {
            self.0[at + i] = le[i];
            i += 1;
        }
    }

    /// Layer index.
    pub fn set_layer(&mut self, v: u32) {
        self.set_u32(0, v);
    }

    /// Tree index (up to 2^68; low 12 bytes LE, high bytes zero).
    ///
    /// The 12-byte field is the normative v2.0 layout. Values below
    /// 2^64 serialize identically to the v1.x 8-byte field, so historical
    /// addresses remain valid.
    pub fn set_tree(&mut self, v: u128) {
        let le = v.to_le_bytes();
        let mut i = 0usize;
        while i < 12 {
            self.0[4 + i] = le[i];
            i += 1;
        }
    }

    /// Address type.
    pub fn set_type(&mut self, v: u32) {
        self.set_u32(16, v);
    }

    /// Generic 32-bit field slots (20/24/28) for per-type data.
    pub fn set_f20(&mut self, v: u32) {
        self.set_u32(20, v);
    }
    /// Generic 32-bit field slot at byte 24.
    pub fn set_f24(&mut self, v: u32) {
        self.set_u32(24, v);
    }
    /// Generic 32-bit field slot at byte 28.
    pub fn set_f28(&mut self, v: u32) {
        self.set_u32(28, v);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fields_round_trip() {
        let mut a = Addr::zero();
        a.set_layer(11);
        a.set_tree(0x1_FFFF_FFFF_FFFF);
        a.set_type(T_WOTS_HASH);
        a.set_f20(31);
        a.set_f24(66);
        a.set_f28(15);
        assert_eq!(&a.0[0..4], &[11, 0, 0, 0]);
        assert_eq!(u32::from(a.0[16]), T_WOTS_HASH);
        assert_eq!(&a.0[20..24], &[31, 0, 0, 0]);
    }
}
