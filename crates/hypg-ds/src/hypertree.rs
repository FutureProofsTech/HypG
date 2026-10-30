//! Hypertree: 17 XMSS layers (`h' = 4` each, total `h = 68`).
//!
//! Layer 0 (bottom) signs the FORS public key; layer `i ≥ 1` signs the
//! child root. Addressing: `tree_i = tree_idx >> (4·(i+1))` (top layer
//! tree 0); `leaf_0 = idx_leaf`, `leaf_i = tree_{i-1} & 15`.

use crate::params::{D, HP, LEAVES, N, WOTS_LEN};
use crate::xmss;

/// Per-layer signature: WOTS sig + auth path.
pub type LayerSig = ([[u8; N]; WOTS_LEN], [[u8; N]; HP]);

/// Sign across all layers. `tree_idx` is the 68-bit hypertree selector,
/// `leaf` the bottom-leaf index, `msg0` the FORS public key.
#[must_use]
pub fn ht_sign(
    pubseed: &[u8; N],
    esk: &[u8; N],
    tree_idx: u128,
    leaf: u32,
    msg0: &[u8; N],
) -> [LayerSig; D] {
    let mut out: [LayerSig; D] = [([[0u8; N]; WOTS_LEN], [[0u8; N]; HP]); D];
    // Fail closed: the bottom leaf index is 4 bits by construction; an
    // out-of-range value must not be turned into a signature over the
    // zero message by the upper layers.
    if leaf as usize >= LEAVES {
        return out;
    }
    let mut msg = *msg0;
    let mut child_tree = tree_idx >> HP;
    let mut i = 0u32;
    while (i as usize) < D {
        let tree = tree_idx >> (HP as u128 * (u128::from(i) + 1));
        let at = if i == 0 {
            leaf
        } else {
            u32::try_from(child_tree & (LEAVES as u128 - 1)).unwrap_or(0)
        };
        let (sig, auth) = xmss::xmss_sign(pubseed, esk, i, tree, at, &msg);
        out[i as usize] = (sig, auth);
        msg = xmss::xmss_verify(pubseed, i, tree, at, &msg, &sig, &auth);
        child_tree = tree;
        i += 1;
    }
    out
}

/// Verify across all layers, returning the top root.
#[must_use]
pub fn ht_verify(
    pubseed: &[u8; N],
    tree_idx: u128,
    leaf: u32,
    msg0: &[u8; N],
    sig: &[LayerSig; D],
) -> [u8; N] {
    // Fail closed: an out-of-range leaf cannot name a real bottom leaf.
    if leaf as usize >= LEAVES {
        return [0u8; N];
    }
    let mut msg = *msg0;
    let mut child_tree = tree_idx >> HP;
    let mut i = 0u32;
    while (i as usize) < D {
        let tree = tree_idx >> (HP as u128 * (u128::from(i) + 1));
        let at = if i == 0 {
            leaf
        } else {
            u32::try_from(child_tree & (LEAVES as u128 - 1)).unwrap_or(0)
        };
        let (wsig, auth) = &sig[i as usize];
        msg = xmss::xmss_verify(pubseed, i, tree, at, &msg, wsig, auth);
        child_tree = tree;
        i += 1;
    }
    msg
}

/// Hypertree public root (top-layer tree only: `LEAVES` WOTS keygens).
#[must_use]
pub fn ht_root(pubseed: &[u8; N], esk: &[u8; N]) -> [u8; N] {
    xmss::xmss_pk(pubseed, esk, u32::try_from(D - 1).unwrap_or(0), 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn out_of_range_leaf_fails_closed() {
        let ps = [0x71u8; N];
        let esk = [0x72u8; N];
        let msg0 = [0x73u8; N];
        let bad = u32::try_from(LEAVES).unwrap_or(u32::MAX);
        let sig = ht_sign(&ps, &esk, 0x12345, bad, &msg0);
        let zero_layer = ([[0u8; N]; WOTS_LEN], [[0u8; N]; HP]);
        let mut i = 0usize;
        while i < D {
            assert_eq!(sig[i], zero_layer);
            i += 1;
        }
        assert_eq!(ht_verify(&ps, 0x12345, bad, &msg0, &sig), [0u8; N]);
    }

    #[test]
    fn hypertree_round_trip() {
        let ps = [0x71u8; N];
        let esk = [0x72u8; N];
        let msg0 = [0x73u8; N];
        let sig = ht_sign(&ps, &esk, 0x12345, 7, &msg0);
        assert_eq!(ht_verify(&ps, 0x12345, 7, &msg0, &sig), ht_root(&ps, &esk));
        // Bit 4 is the low bit of the bottom-layer tree selector —
        // flipping it must change the root.
        assert_ne!(ht_verify(&ps, 0x12355, 7, &msg0, &sig), ht_root(&ps, &esk));
    }
}
