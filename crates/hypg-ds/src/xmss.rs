//! XMSS Merkle layer (`h' = 4`, 16 WOTS+ keypairs).
//!
//! Addresses: layer/tree carried in `base`; per-keypair WOTS base sets
//! the keypair index. TREE-type nodes carry `(height, index)`.

use crate::addr::{Addr, T_TREE};
use crate::params::{HP, LEAVES, N, WOTS_LEN};
use crate::thash::h;
use crate::wots;
use hypg_core::ct::zeroize_nested;

/// XMSS public root from secret (builds the full 16-leaf tree).
#[must_use]
pub fn xmss_pk(pubseed: &[u8; N], esk: &[u8; N], layer: u32, tree: u128) -> [u8; N] {
    let mut level = [[0u8; N]; LEAVES];
    let mut i = 0u32;
    while (i as usize) < LEAVES {
        level[i as usize] = leaf_pk(pubseed, esk, layer, tree, i);
        i += 1;
    }
    merkle_root(pubseed, &mut level, layer, tree)
}

/// WOTS+ L-tree leaf for keypair `idx`.
fn leaf_pk(pubseed: &[u8; N], esk: &[u8; N], layer: u32, tree: u128, idx: u32) -> [u8; N] {
    let mut base = Addr::zero();
    base.set_layer(layer);
    base.set_tree(tree);
    base.set_f20(idx);
    let mut sk = wots::gen_sk(pubseed, esk, &base);
    let pk = wots::pk_from_sk(pubseed, &sk, &base);
    let leaf = wots::ltree(pubseed, &pk, &base);
    zeroize_nested(&mut sk);
    leaf
}

/// WOTS+ keypair (secret + L-tree leaf) for keypair `idx`.
/// Lets signing reuse the leaf's secret instead of regenerating it.
fn leaf_keypair(
    pubseed: &[u8; N],
    esk: &[u8; N],
    layer: u32,
    tree: u128,
    idx: u32,
) -> ([[u8; N]; WOTS_LEN], [u8; N]) {
    let mut base = Addr::zero();
    base.set_layer(layer);
    base.set_tree(tree);
    base.set_f20(idx);
    let sk = wots::gen_sk(pubseed, esk, &base);
    let pk = wots::pk_from_sk(pubseed, &sk, &base);
    (sk, wots::ltree(pubseed, &pk, &base))
}

/// Merkle root over `LEAVES` leaves in place.
fn merkle_root(
    pubseed: &[u8; N],
    level: &mut [[u8; N]; LEAVES],
    layer: u32,
    tree: u128,
) -> [u8; N] {
    let mut width = LEAVES;
    let mut height = 0u32;
    while width > 1 {
        let mut i = 0usize;
        let mut p = 0u32;
        while i < width {
            let mut a = Addr::zero();
            a.set_layer(layer);
            a.set_tree(tree);
            a.set_type(T_TREE);
            a.set_f24(height);
            a.set_f28(p);
            level[i / 2] = h(pubseed, &a, &level[i], &level[i + 1]);
            p += 1;
            i += 2;
        }
        width /= 2;
        height += 1;
    }
    level[0]
}

/// XMSS signature: WOTS sig at `idx` plus `HP`-node auth path.
#[must_use]
pub fn xmss_sign(
    pubseed: &[u8; N],
    esk: &[u8; N],
    layer: u32,
    tree: u128,
    idx: u32,
    msg: &[u8; N],
) -> ([[u8; N]; WOTS_LEN], [[u8; N]; HP]) {
    // Fail closed: out-of-range leaf indices never sign (no zeroed leaf
    // secret is used) and produce a signature that cannot verify.
    if idx as usize >= LEAVES {
        return ([[0u8; N]; WOTS_LEN], [[0u8; N]; HP]);
    }
    // Full tree (`LEAVES` leaves) — simple and stack-resident. The signed
    // leaf's secret is kept for signing below (saves one regeneration).
    let mut level = [[0u8; N]; LEAVES];
    let mut leaf_sk = [[0u8; N]; WOTS_LEN];
    let mut i = 0u32;
    while (i as usize) < LEAVES {
        if i == idx {
            let (sk, leaf) = leaf_keypair(pubseed, esk, layer, tree, i);
            leaf_sk = sk;
            level[i as usize] = leaf;
        } else {
            level[i as usize] = leaf_pk(pubseed, esk, layer, tree, i);
        }
        i += 1;
    }
    let mut base = Addr::zero();
    base.set_layer(layer);
    base.set_tree(tree);
    base.set_f20(idx);
    let digits = wots::digits(msg);
    let sig = wots::sign(pubseed, &leaf_sk, &digits, &base);
    zeroize_nested(&mut leaf_sk);
    // Auth path: sibling at each height (public indices).
    let mut auth = [[0u8; N]; HP];
    let mut node = idx as usize;
    let mut width = LEAVES;
    let mut height = 0u32;
    // Recompute internal levels in a side buffer.
    let mut work = level;
    while width > 1 {
        let sib = if node % 2 == 0 { node + 1 } else { node - 1 };
        auth[height as usize] = work[sib];
        let mut i = 0usize;
        let mut p = 0u32;
        while i < width {
            let mut a = Addr::zero();
            a.set_layer(layer);
            a.set_tree(tree);
            a.set_type(T_TREE);
            a.set_f24(height);
            a.set_f28(p);
            work[i / 2] = h(pubseed, &a, &work[i], &work[i + 1]);
            p += 1;
            i += 2;
        }
        node /= 2;
        width /= 2;
        height += 1;
    }
    (sig, auth)
}

/// Build all `LEAVES` WOTS L-tree leaves of one XMSS tree.
///
/// Parallel building block for threaded signers (`hypg-mt`): leaf builds
/// are pure functions of `(pubseed, esk, layer, tree)` and independent.
/// Byte-identical to the leaves `xmss_sign` builds internally.
#[must_use]
pub fn xmss_build(pubseed: &[u8; N], esk: &[u8; N], layer: u32, tree: u128) -> [[u8; N]; LEAVES] {
    let mut level = [[0u8; N]; LEAVES];
    let mut i = 0u32;
    while (i as usize) < LEAVES {
        level[i as usize] = leaf_pk(pubseed, esk, layer, tree, i);
        i += 1;
    }
    level
}

/// Sign with prebuilt leaves (from [`xmss_build`]): WOTS-sign the leaf at
/// `idx`, then capture the auth path in one bottom-up pass.
/// Output is byte-identical to [`xmss_sign`].
#[must_use]
pub fn xmss_sign_with_leaves(
    pubseed: &[u8; N],
    esk: &[u8; N],
    layer: u32,
    tree: u128,
    idx: u32,
    msg: &[u8; N],
    leaves: &[[u8; N]; LEAVES],
) -> ([[u8; N]; WOTS_LEN], [[u8; N]; HP]) {
    if idx as usize >= LEAVES {
        return ([[0u8; N]; WOTS_LEN], [[0u8; N]; HP]);
    }
    let mut base = Addr::zero();
    base.set_layer(layer);
    base.set_tree(tree);
    base.set_f20(idx);
    let mut sk = wots::gen_sk(pubseed, esk, &base);
    let digits = wots::digits(msg);
    let sig = wots::sign(pubseed, &sk, &digits, &base);
    zeroize_nested(&mut sk);
    let mut auth = [[0u8; N]; HP];
    let mut node = idx as usize;
    let mut width = LEAVES;
    let mut height = 0u32;
    let mut work = *leaves;
    while width > 1 {
        let sib = if node % 2 == 0 { node + 1 } else { node - 1 };
        auth[height as usize] = work[sib];
        let mut i = 0usize;
        let mut p = 0u32;
        while i < width {
            let mut a = Addr::zero();
            a.set_layer(layer);
            a.set_tree(tree);
            a.set_type(T_TREE);
            a.set_f24(height);
            a.set_f28(p);
            work[i / 2] = h(pubseed, &a, &work[i], &work[i + 1]);
            p += 1;
            i += 2;
        }
        node /= 2;
        width /= 2;
        height += 1;
    }
    (sig, auth)
}

/// XMSS verify: recompute leaf from WOTS sig, climb with auth path.
#[must_use]
pub fn xmss_verify(
    pubseed: &[u8; N],
    layer: u32,
    tree: u128,
    idx: u32,
    msg: &[u8; N],
    sig: &[[u8; N]; WOTS_LEN],
    auth: &[[u8; N]; HP],
) -> [u8; N] {
    // Fail closed: an out-of-range leaf index cannot name a real leaf.
    if idx as usize >= LEAVES {
        return [0u8; N];
    }
    let mut base = Addr::zero();
    base.set_layer(layer);
    base.set_tree(tree);
    base.set_f20(idx);
    let digits = wots::digits(msg);
    let pk = wots::pk_from_sig(pubseed, sig, &digits, &base);
    let mut node = wots::ltree(pubseed, &pk, &base);
    let mut at = idx;
    let mut height = 0u32;
    while (height as usize) < HP {
        let mut a = Addr::zero();
        a.set_layer(layer);
        a.set_tree(tree);
        a.set_type(T_TREE);
        a.set_f24(height);
        a.set_f28(at / 2);
        if at % 2 == 0 {
            node = h(pubseed, &a, &node, &auth[height as usize]);
        } else {
            node = h(pubseed, &a, &auth[height as usize], &node);
        }
        at /= 2;
        height += 1;
    }
    node
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn xmss_round_trip() {
        let ps = [0x51u8; N];
        let esk = [0x52u8; N];
        let msg = [0x53u8; N];
        let root = xmss_pk(&ps, &esk, 0, 7);
        let (sig, auth) = xmss_sign(&ps, &esk, 0, 7, 3, &msg);
        assert_eq!(xmss_verify(&ps, 0, 7, 3, &msg, &sig, &auth), root);
        // Wrong index must not verify to the same root.
        assert_ne!(xmss_verify(&ps, 0, 7, 4, &msg, &sig, &auth), root);
    }

    #[test]
    fn idx_boundaries_round_trip() {
        // Edge leaves: all-left (`0`) and all-right (`LEAVES - 1`) auth-path
        // climbs — the classic off-by-one sites for sibling selection.
        let ps = [0x51u8; N];
        let esk = [0x52u8; N];
        let msg = [0x53u8; N];
        let root = xmss_pk(&ps, &esk, 0, 7);
        for idx in [0u32, u32::try_from(LEAVES - 1).unwrap_or(0)] {
            let (sig, auth) = xmss_sign(&ps, &esk, 0, 7, idx, &msg);
            assert_eq!(xmss_verify(&ps, 0, 7, idx, &msg, &sig, &auth), root, "boundary idx {idx}");
            // Neighbor index must not verify to the same root.
            let wrong = if idx == 0 { 1 } else { u32::try_from(LEAVES - 2).unwrap_or(0) };
            assert_ne!(xmss_verify(&ps, 0, 7, wrong, &msg, &sig, &auth), root);
        }
    }

    #[test]
    fn out_of_range_index_fails_closed() {
        let ps = [0x51u8; N];
        let esk = [0x52u8; N];
        let msg = [0x53u8; N];
        let bad = u32::try_from(LEAVES).unwrap_or(u32::MAX);
        let (sig, auth) = xmss_sign(&ps, &esk, 0, 7, bad, &msg);
        assert_eq!(sig, [[0u8; N]; WOTS_LEN]);
        assert_eq!(auth, [[0u8; N]; HP]);
        assert_eq!(xmss_verify(&ps, 0, 7, bad, &msg, &sig, &auth), [0u8; N]);
        // The prebuilt-leaf path must reject before touching `leaves`;
        // a dummy all-zero tree is sufficient (normal path is covered by
        // `split_path_matches_monolith`).
        let leaves = [[0u8; N]; LEAVES];
        let (sig2, auth2) = xmss_sign_with_leaves(&ps, &esk, 0, 7, bad, &msg, &leaves);
        assert_eq!(sig2, [[0u8; N]; WOTS_LEN]);
        assert_eq!(auth2, [[0u8; N]; HP]);
    }

    #[test]
    fn split_path_matches_monolith() {
        // `xmss_build` + `xmss_sign_with_leaves` must equal `xmss_sign`
        // byte-for-byte (the parallel driver relies on this).
        let ps = [0x51u8; N];
        let esk = [0x52u8; N];
        let msg = [0x53u8; N];
        for idx in [0u32, 1, 7, u32::try_from(LEAVES - 1).unwrap_or(0)] {
            let (s1, a1) = xmss_sign(&ps, &esk, 2, 9, idx, &msg);
            let leaves = xmss_build(&ps, &esk, 2, 9);
            let (s2, a2) = xmss_sign_with_leaves(&ps, &esk, 2, 9, idx, &msg, &leaves);
            assert_eq!((s1, a1), (s2, a2), "split mismatch at idx {idx}");
        }
    }
}
