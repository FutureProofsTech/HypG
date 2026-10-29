//! `hypg-mt`: threaded DS signer (std library crate, zero-dep).
//!
//! `mt_sign` computes byte-identical output to `hypg_ds::ds_sign` by
//! running the independent tree builds on scoped threads:
//! `D` XMSS layer builds + `FORS_K` FORS tree builds (the ~90% bulk), with the
//! fast digest + serial assembly unchanged. See `docs/threading.md` for
//! the model (`no_std` boundary, determinism argument, worker sizing).
//!
//! Threading lives here — never in the `no_std` libraries — because
//! threads are a platform capability (OS scheduler + 8 MB stacks),
//! not a cryptographic primitive.

use hypg_ds::fors::{fors_sign_one, fors_verify, ForsSig};
use hypg_ds::params::{D, FORS_A, FORS_K, HP, LEAVES, WOTS_LEN};
use hypg_ds::xmss::{xmss_build, xmss_sign_with_leaves, xmss_verify};
use hypg_ds::{pre_sign, serialize_sig, LayerSig, PreSign, SigSk, SIG_LEN};

/// One FORS tree signature unit: `(secret leaf, auth path)`.
type ForsUnit = ([u8; 32], [[u8; 32]; FORS_A]);
/// One XMSS tree's `LEAVES` WOTS leaves.
type XmssLeaves = [[u8; 32]; LEAVES];

/// Parallel work unit: an independent tree build.
/// `Xmss(layer)` builds `LEAVES` WOTS leaves; `Fors(tree)` signs one tree.
#[derive(Clone, Copy, Debug)]
enum Unit {
    Xmss(u32),
    Fors(u32),
}

/// Worker count: platform parallelism, clamped to `[1, 64]`.
/// Overridable with `HYPG_MT_WORKERS` (used by tests across 1/2/4/max).
#[must_use]
pub fn worker_count() -> usize {
    if let Ok(v) = std::env::var("HYPG_MT_WORKERS") {
        if let Ok(n) = v.parse::<usize>() {
            if (1..=64).contains(&n) {
                return n;
            }
        }
    }
    std::thread::available_parallelism().map_or(4, |n| n.get().min(64))
}

/// Threaded sign into `sig_out` (exact `SIG_LEN` bytes, caller buffer).
/// Output is byte-identical to serial `ds_sign` for every `(sk, msg)`.
///
/// # Example
///
/// ```rust
/// use hypg_ds::{ds_keygen, ds_verify, SIG_LEN};
/// use hypg_mt::mt_sign;
///
/// let (pk, sk) = ds_keygen(&[0x43u8; 32]);
/// let mut sig = Box::new([0u8; SIG_LEN]); // heap-boxed immediately
/// mt_sign(&sk, b"hello hypg-mt", &mut sig);
/// assert!(ds_verify(&pk, b"hello hypg-mt", &sig[..]));
/// ```
///
/// # Panics
///
/// Never panics: worker results are pure computation, so a lost thread
/// (platform failure, never a crypto error) falls back to serial
/// recomputation of that worker's chunk in the joining thread.
pub fn mt_sign(sk: &SigSk, msg: &[u8], sig_out: &mut [u8; SIG_LEN]) {
    let workers = worker_count().min(D + FORS_K);
    mt_sign_with_workers(sk, msg, sig_out, workers.max(1));
}

/// One worker's strided chunk, computed serially: worker `w` takes units
/// `w, w+workers, ...`. Used by spawned threads and as the join-failure
/// fallback (identical assignment, so the fallback output is identical).
#[allow(clippy::type_complexity)]
fn compute_chunk(
    ctx: &PreSign,
    units: &[Unit],
    workers: usize,
    w: usize,
) -> (Vec<(u32, XmssLeaves)>, Vec<(u32, ForsUnit)>) {
    let mut xm: Vec<(u32, XmssLeaves)> = Vec::new();
    let mut fo: Vec<(u32, ForsUnit)> = Vec::new();
    let mut i = w;
    while i < units.len() {
        match units[i] {
            Unit::Xmss(layer) => {
                let tree = ctx.tree_idx >> (HP as u128 * (u128::from(layer) + 1));
                xm.push((layer, xmss_build(&ctx.pubseed, &ctx.esk, layer, tree)));
            }
            Unit::Fors(tree) => {
                fo.push((
                    tree,
                    fors_sign_one(&ctx.pubseed, &ctx.esk, tree, ctx.fors_idx[tree as usize]),
                ));
            }
        }
        i += workers;
    }
    (xm, fo)
}

/// Threaded sign with an explicit worker count (`1..=64`).
/// `workers == 1` still exercises the scatter/gather path; output is
/// byte-identical for every count. Out-of-range counts clamp.
///
/// # Panics
///
/// Never panics (see [`mt_sign`]).
pub fn mt_sign_with_workers(sk: &SigSk, msg: &[u8], sig_out: &mut [u8; SIG_LEN], workers: usize) {
    let workers = workers.clamp(1, 64);
    let ctx = pre_sign(sk, msg);
    // `D + FORS_K` independent units, strided across workers for balance
    // (XMSS builds are ~100× heavier than FORS builds).
    let mut units = Vec::with_capacity(D + FORS_K);
    let mut l = 0u32;
    while (l as usize) < D {
        units.push(Unit::Xmss(l));
        l += 1;
    }
    let mut t = 0u32;
    while (t as usize) < FORS_K {
        units.push(Unit::Fors(t));
        t += 1;
    }
    let workers = workers.min(units.len());
    // Owned per-unit outputs, assembled in index order after joining —
    // thread scheduling cannot affect the bytes.
    let mut xmss_leaves: Vec<Option<XmssLeaves>> = (0..D).map(|_| None).collect();
    let mut fors_units: Vec<Option<ForsUnit>> = (0..FORS_K).map(|_| None).collect();
    std::thread::scope(|s| {
        let mut handles = Vec::with_capacity(workers);
        for w in 0..workers {
            // Strided slice: worker `w` takes units `w, w+W, ...`
            // (see `compute_chunk`). Shared refs are `Copy` into the
            // `move` closure; scoped threads may borrow locals.
            let ctx_r = &ctx;
            let units_r = &units;
            let handle = s.spawn(move || compute_chunk(ctx_r, units_r, workers, w));
            handles.push(handle);
        }
        for (w, h) in handles.into_iter().enumerate() {
            // Join failure means a worker thread was lost (platform
            // failure); recompute its chunk serially — same assignment,
            // same bytes, no panic.
            let (xm, fo) = match h.join() {
                Ok(r) => r,
                Err(_) => compute_chunk(&ctx, &units, workers, w),
            };
            for (layer, leaves) in xm {
                xmss_leaves[layer as usize] = Some(leaves);
            }
            for (tree, unit) in fo {
                fors_units[tree as usize] = Some(unit);
            }
        }
    });
    // Serial assembly (fast: WOTS signs + climbs + serialize). Any slot
    // still empty (only after a double platform failure) is computed
    // serially, so assembly is total without panicking.
    let mut fsig: ForsSig = [([0u8; 32], [[0u8; 32]; FORS_A]); FORS_K];
    let mut t = 0u32;
    while (t as usize) < FORS_K {
        fsig[t as usize] = match fors_units[t as usize] {
            Some(u) => u,
            None => fors_sign_one(&ctx.pubseed, &ctx.esk, t, ctx.fors_idx[t as usize]),
        };
        t += 1;
    }
    let fors_pk = fors_verify(&ctx.pubseed, &ctx.fors_idx, &fsig);
    #[allow(clippy::large_stack_arrays)]
    let mut ht_sig: Box<[LayerSig; D]> = Box::new([([[0u8; 32]; WOTS_LEN], [[0u8; 32]; HP]); D]); // heap-boxed immediately
    let mut msg = fors_pk;
    let mut child_tree = ctx.tree_idx >> HP;
    let mut l = 0u32;
    while (l as usize) < D {
        let tree = ctx.tree_idx >> (HP as u128 * (u128::from(l) + 1));
        let at = if l == 0 {
            ctx.leaf
        } else {
            u32::try_from(child_tree & (LEAVES as u128 - 1)).unwrap_or(0)
        };
        // Same totality rule as the FORS assembly above: recompute a
        // lost unit serially instead of panicking.
        let leaves_owned: XmssLeaves = match xmss_leaves[l as usize] {
            Some(x) => x,
            None => xmss_build(&ctx.pubseed, &ctx.esk, l, tree),
        };
        let leaves = &leaves_owned;
        let (wsig, auth) = xmss_sign_with_leaves(&ctx.pubseed, &ctx.esk, l, tree, at, &msg, leaves);
        ht_sig[l as usize] = (wsig, auth);
        msg = xmss_verify(&ctx.pubseed, l, tree, at, &msg, &wsig, &auth);
        child_tree = tree;
        l += 1;
    }
    serialize_sig(&ctx.r, &fsig, &ht_sig, sig_out);
}

#[cfg(test)]
mod tests {
    use super::*;
    use hypg_ds::{ds_keygen, ds_sign, ds_verify};

    fn check_case(seed_byte: u8, msg: &[u8]) {
        let (_, sk) = ds_keygen(&[seed_byte; 32]);
        #[allow(clippy::large_stack_arrays)]
        let mut s1 = Box::new([0u8; SIG_LEN]); // heap-boxed immediately
        #[allow(clippy::large_stack_arrays)]
        let mut s2 = Box::new([0u8; SIG_LEN]); // heap-boxed immediately
        ds_sign(&sk, msg, &mut s1);
        mt_sign(&sk, msg, &mut s2);
        assert_eq!(*s1, *s2, "mt/serial divergence");
        let (pk, _) = ds_keygen(&[seed_byte; 32]);
        assert!(ds_verify(&pk, msg, &s2[..]));
    }

    #[test]
    fn mt_matches_serial() {
        check_case(0x42, b"");
        check_case(0x42, b"hello hypg-mt");
        check_case(0xFF, b"");
        let mut big = [0u8; 1500];
        let mut i = 0u32;
        while i < 1500 {
            big[i as usize] = u8::try_from(i * 3 + 1).unwrap_or(0);
            i += 1;
        }
        check_case(0x07, &big);
    }

    #[test]
    fn mt_stable_across_worker_counts() {
        // Same bytes with 1, 2, and 64 workers (no env manipulation —
        // explicit counts keep parallel tests hermetic).
        let (_, sk) = ds_keygen(&[0x42u8; 32]);
        #[allow(clippy::large_stack_arrays)]
        let mut reference = Box::new([0u8; SIG_LEN]); // heap-boxed immediately
        ds_sign(&sk, b"workers", &mut reference);
        for w in [1usize, 2, 64] {
            #[allow(clippy::large_stack_arrays)]
            let mut s = Box::new([0u8; SIG_LEN]); // heap-boxed immediately
            mt_sign_with_workers(&sk, b"workers", &mut s, w);
            assert_eq!(*s, *reference, "worker count {w} diverged");
        }
    }
}
