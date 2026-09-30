//! Hypertree: 12 XMSS layers (`h' = 5` each, total `h = 60`).
//!
//! Layer 0 (bottom) signs the FORS public key; layer `i ≥ 1` signs the
//! child root. Addressing: `tree_i = tree_idx >> (5·(i+1))` (top layer
//! tree 0); `leaf_0 = idx_leaf`, `leaf_i = tree_{i-1} & 31`.

use crate::params::{D, HP, N};
use crate::xmss;

/// Per-layer signature: WOTS sig + auth path.
pub type LayerSig = ([[u8; N]; 67], [[u8; N]; HP]);

/// Sign across all layers. `tree_idx` is the 60-bit hypertree selector,
/// `leaf` the bottom-leaf index, `msg0` the FORS public key.
#[must_use]
pub fn ht_sign(
    pubseed: &[u8; N],
    esk: &[u8; N],
    tree_idx: u64,
    leaf: u32,
    msg0: &[u8; N],
) -> [LayerSig; D] {
    let mut out: [LayerSig; D] = [([[0u8; N]; 67], [[0u8; N]; HP]); D];
    let mut msg = *msg0;
    let mut child_tree = tree_idx >> HP;
    let mut i = 0u32;
    while (i as usize) < D {
        let tree = tree_idx >> (HP as u64 * (u64::from(i) + 1));
        let at = if i == 0 { leaf } else { u32::try_from(child_tree & 31).unwrap_or(0) };
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
    tree_idx: u64,
    leaf: u32,
    msg0: &[u8; N],
    sig: &[LayerSig; D],
) -> [u8; N] {
    let mut msg = *msg0;
    let mut child_tree = tree_idx >> HP;
    let mut i = 0u32;
    while (i as usize) < D {
        let tree = tree_idx >> (HP as u64 * (u64::from(i) + 1));
        let at = if i == 0 { leaf } else { u32::try_from(child_tree & 31).unwrap_or(0) };
        let (wsig, auth) = &sig[i as usize];
        msg = xmss::xmss_verify(pubseed, i, tree, at, &msg, wsig, auth);
        child_tree = tree;
        i += 1;
    }
    msg
}

/// Hypertree public root (top-layer tree only: 32 WOTS keygens).
#[must_use]
pub fn ht_root(pubseed: &[u8; N], esk: &[u8; N]) -> [u8; N] {
    xmss::xmss_pk(pubseed, esk, u32::try_from(D - 1).unwrap_or(0), 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hypertree_round_trip() {
        let ps = [0x71u8; N];
        let esk = [0x72u8; N];
        let msg0 = [0x73u8; N];
        let sig = ht_sign(&ps, &esk, 0x12345, 7, &msg0);
        assert_eq!(ht_verify(&ps, 0x12345, 7, &msg0, &sig), ht_root(&ps, &esk));
        // Bit 5 selects the bottom-layer tree — flipping it must change the root.
        assert_ne!(ht_verify(&ps, 0x12365, 7, &msg0, &sig), ht_root(&ps, &esk));
    }
}
