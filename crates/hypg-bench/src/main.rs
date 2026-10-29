//! `hypg-bench`: throughput + timing-leakage harness (std binary, zero-dep).
//!
//! Reports integer-average wall times for KEM `keygen`/`encaps`/`decaps`
//! and Symm `seal`/`open`, a valid-vs-tampered median ratio smoke signal,
//! and (with `HYPG_BENCH_TTEST_N`) a Welch t-test over interleaved
//! valid/tampered timings in the `dudect` spirit. The t-test is
//! informational: this binary exits non-zero only on functional failure,
//! never on timing. Floats are confined to this std harness; libraries
//! stay float-free.

use std::time::Instant;

use hypg_core::params::{C1_PACKED_LEN, C1_VEC_PACKED_LEN, CT_LEN};
use hypg_kem::{decaps, encaps, keygen};
use hypg_symm::{open, seal, Key, Nonce, TAG_LEN};

fn iters() -> u64 {
    std::env::var("HYPG_BENCH_ITERS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .filter(|&n| (2..=10_000).contains(&n))
        .unwrap_or(20)
}

/// Welch t-test sample count (0 = disabled). Kept separate from `iters`
/// because leakage statistics need far more samples than throughput averages.
fn ttest_n() -> u64 {
    std::env::var("HYPG_BENCH_TTEST_N")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .filter(|&n| (100..=100_000).contains(&n))
        .unwrap_or(0)
}

/// DS bench iterations (signing is hypertree-heavy; default 1 in debug,
/// override for release measurements).
fn ds_iters() -> u64 {
    std::env::var("HYPG_BENCH_DS_ITERS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .filter(|&n| (1..=100).contains(&n))
        .unwrap_or(1)
}

/// Breakdown profiler (`HYPG_BENCH_PROFILE=1`): attributes DS signing cost
/// to sub-operations using only public APIs, plus BLAKE3 and `CA-PRF`
/// micro-costs. Off by default (seconds in debug, not CI).
fn profile_on() -> bool {
    std::env::var("HYPG_BENCH_PROFILE").is_ok_and(|v| v == "1")
}

fn median(mut v: Vec<u128>) -> u128 {
    v.sort_unstable();
    v[v.len() / 2]
}

/// Symm throughput over a 1 KiB message + forged-tag timing smoke.
fn symm_bench(n: u64) {
    let skey = Key([0x42u8; 32]);
    let snonce = Nonce([0x11u8; 12]);
    let spt = [0xA5u8; 1024];
    let mut sct = [0u8; 1024];
    let mut stag = [0u8; TAG_LEN];
    let mut sback = [0u8; 1024];
    assert!(seal(&skey, &snonce, b"bench-ad", &spt, &mut sct, &mut stag).is_some());
    assert!(open(&skey, &snonce, b"bench-ad", &sct, &stag, &mut sback).is_some());
    assert_eq!(sback, spt);
    let t = Instant::now();
    for _ in 0..n {
        let _ = seal(&skey, &snonce, b"bench-ad", &spt, &mut sct, &mut stag);
    }
    let seal_us = t.elapsed().as_micros() / u128::from(n);
    let t = Instant::now();
    for _ in 0..n {
        let _ = open(&skey, &snonce, b"bench-ad", &sct, &stag, &mut sback);
    }
    let open_us = t.elapsed().as_micros() / u128::from(n);
    let mut bad_tag = stag;
    bad_tag[0] ^= 0x01;
    let mut v_ns: Vec<u128> = Vec::new();
    let mut f_ns: Vec<u128> = Vec::new();
    for _ in 0..n {
        let t = Instant::now();
        let _ = open(&skey, &snonce, b"bench-ad", &sct, &stag, &mut sback);
        v_ns.push(t.elapsed().as_nanos());
        let t = Instant::now();
        let _ = open(&skey, &snonce, b"bench-ad", &sct, &bad_tag, &mut sback);
        f_ns.push(t.elapsed().as_nanos());
    }
    let (mv, mf) = (median(v_ns).max(1), median(f_ns).max(1));
    println!("avg_us: seal_1kib = {seal_us} open_1kib = {open_us}");
    println!(
        "open_median_ns: valid = {mv} forged = {mf} (ratio pm = {})",
        mf.saturating_mul(1000) / mv
    );
}

/// DS throughput (hypertree signing dominates; few iterations).
fn ds_bench() {
    use hypg_ds::{ds_keygen, ds_sign, ds_verify, SIG_LEN};
    use hypg_mt::mt_sign;
    let n = ds_iters();
    let (pk, sk) = ds_keygen(&[0x42u8; 32]);
    let msg = b"bench message for hypertree signing";
    #[allow(clippy::large_stack_arrays)]
    let mut sig = Box::new([0u8; SIG_LEN]); // heap-boxed immediately
    ds_sign(&sk, msg, &mut sig);
    assert!(ds_verify(&pk, msg, &sig[..]));
    let t = Instant::now();
    for _ in 0..n {
        ds_sign(&sk, msg, &mut sig);
    }
    let sign_us = t.elapsed().as_micros() / u128::from(n);
    let t = Instant::now();
    for _ in 0..n {
        assert!(ds_verify(&pk, msg, &sig[..]));
    }
    let verify_us = t.elapsed().as_micros() / u128::from(n);
    println!("avg_us (n={n}): ds_sign = {sign_us} ds_verify = {verify_us}");
    // Valid-vs-forged verify timing smoke (mirrors the KEM/symm pairs):
    // forged sigs exit at different parse stages, medians expose it.
    let mut bad_sig = sig.clone();
    bad_sig[0] ^= 0x01;
    assert!(!ds_verify(&pk, msg, &bad_sig[..]));
    let mut valid_ns: Vec<u128> = Vec::new();
    let mut forged_ns: Vec<u128> = Vec::new();
    for _ in 0..n {
        let t = Instant::now();
        assert!(ds_verify(&pk, msg, &sig[..]));
        valid_ns.push(t.elapsed().as_nanos());
        let t = Instant::now();
        assert!(!ds_verify(&pk, msg, &bad_sig[..]));
        forged_ns.push(t.elapsed().as_nanos());
    }
    let (mv, mf) = (median(valid_ns).max(1), median(forged_ns).max(1));
    println!(
        "ds_verify_median_ns: valid = {mv} forged = {mf} (ratio pm = {})",
        mf.saturating_mul(1000) / mv
    );
    // Threaded signing: same bytes (asserted), strided scope. Speedup is
    // per-mille vs serial (1000 = identical) — informational only.
    mt_sign(&sk, msg, &mut sig);
    assert!(ds_verify(&pk, msg, &sig[..]));
    let t = Instant::now();
    for _ in 0..n {
        mt_sign(&sk, msg, &mut sig);
    }
    let mt_us = t.elapsed().as_micros() / u128::from(n);
    let workers = hypg_mt::worker_count();
    let speedup_pm = sign_us.saturating_mul(1000) / mt_us.max(1);
    println!("avg_us (n={n}): ds_mt_sign = {mt_us} workers = {workers} speedup_pm = {speedup_pm}");
}

/// Large-message throughput at 1 MiB (integer MB/s): one-shot hash,
/// chunked streaming hash (64 KiB updates — proves no packaging cliff
/// at chunk/buffer boundaries), XOF output, raw `ChaCha` keystream, and
/// AEAD seal/open. Fixed 3 reps keep debug CI fast; release numbers
/// are the recorded claim (>100 MB/s bar per primitive).
fn big_bench() {
    use hypg_core::b3::{b3_hash, b3_xof, Hasher};
    use hypg_core::chacha::xor_in_place;
    const BIG: usize = 1 << 20;
    const REPS: u128 = 3;
    let pt = vec![0xA5u8; BIG];
    // Integer MB/s: total bytes over total microseconds (1 B/µs = 1 MB/s).
    let rate = |total_us: u128| (BIG as u128).saturating_mul(REPS) / total_us.max(1);
    let t = Instant::now();
    for _ in 0..REPS {
        let mut out = [0u8; 32];
        b3_hash(&pt, &mut out);
    }
    println!(
        "big_1mib: b3_hash MB/s = {} (us per op = {})",
        rate(t.elapsed().as_micros()),
        t.elapsed().as_micros() / REPS
    );
    let t = Instant::now();
    for _ in 0..REPS {
        let mut h = Hasher::new();
        for chunk in pt.chunks(64 << 10) {
            h.update(chunk);
        }
        let _ = h.finalize32();
    }
    println!(
        "big_1mib: b3_streaming MB/s = {} (us per op = {})",
        rate(t.elapsed().as_micros()),
        t.elapsed().as_micros() / REPS
    );
    let t = Instant::now();
    for _ in 0..REPS {
        let mut out = vec![0u8; BIG];
        b3_xof(&mut out, b"big-xof-input");
    }
    println!(
        "big_1mib: b3_xof MB/s = {} (us per op = {})",
        rate(t.elapsed().as_micros()),
        t.elapsed().as_micros() / REPS
    );
    let key = [0x42u8; 32];
    let nonce = [0x11u8; 12];
    let t = Instant::now();
    for _ in 0..REPS {
        let mut buf = pt.clone();
        assert_eq!(xor_in_place(&key, &nonce, 0, &mut buf), BIG);
    }
    println!(
        "big_1mib: chacha_xor MB/s = {} (us per op = {})",
        rate(t.elapsed().as_micros()),
        t.elapsed().as_micros() / REPS
    );
    let akey = Key([0x42u8; 32]);
    let anonce = Nonce([0x11u8; 12]);
    let mut ct = vec![0u8; BIG];
    let mut back = vec![0u8; BIG];
    let mut tag = [0u8; TAG_LEN];
    assert!(seal(&akey, &anonce, b"big-ad", &pt, &mut ct, &mut tag).is_some());
    assert!(open(&akey, &anonce, b"big-ad", &ct, &tag, &mut back).is_some());
    assert_eq!(back, pt);
    let t = Instant::now();
    for _ in 0..REPS {
        let _ = seal(&akey, &anonce, b"big-ad", &pt, &mut ct, &mut tag);
    }
    println!(
        "big_1mib: seal MB/s = {} (us per op = {})",
        rate(t.elapsed().as_micros()),
        t.elapsed().as_micros() / REPS
    );
    let t = Instant::now();
    for _ in 0..REPS {
        let _ = open(&akey, &anonce, b"big-ad", &ct, &tag, &mut back);
    }
    println!(
        "big_1mib: open MB/s = {} (us per op = {})",
        rate(t.elapsed().as_micros()),
        t.elapsed().as_micros() / REPS
    );
}

/// Cost breakdown (public APIs only): attributes DS signing time to
/// FORS vs one XMSS layer vs one WOTS+ key, plus BLAKE3 and `CA-PRF`
/// micro-costs. Integer microseconds; informational only.
fn ds_profile() {
    use hypg_ds::{addr::Addr, fors, params::N, wots, xmss};
    let ps = [0x42u8; N];
    let esk = [0x43u8; N];
    let base = Addr::zero();

    // Hash rate: 128 B input compresses in one BLAKE3 block.
    // 20000 iterations for sub-microsecond resolution.
    let buf = [0xA5u8; 128];
    let mut out = [0u8; 32];
    let t = Instant::now();
    let mut i = 0u32;
    while i < 20_000 {
        hypg_symm::symm_hash(&buf, &mut out);
        i += 1;
    }
    let total_ns = t.elapsed().as_nanos();
    // Nanosecond per permutation, integer + remainder thousandths.
    let ns_per_perm = total_ns / 20_000;
    println!("profile: b3_128B_ns_per_hash = {ns_per_perm}");

    // `CA-PRF` (XOF + CA + KDF) vs plain KDF over the same output length.
    let mut big = [0u8; 1536];
    let t = Instant::now();
    hypg_core::caprf::ca_expand(&mut big, &esk, b"profile");
    let caprf_us = t.elapsed().as_micros();
    let zeros = [0u8; 256];
    let t = Instant::now();
    hypg_core::b3::b3_kdf(&mut big, &[zeros.as_slice()], b"profile");
    let kdf_us = t.elapsed().as_micros();
    println!("profile: ca_expand_1536B_us = {caprf_us} kdf_1536B_us = {kdf_us}");

    // One WOTS+ key (gen + full chains + L-tree).
    let t = Instant::now();
    let sk = wots::gen_sk(&ps, &esk, &base);
    let pk = wots::pk_from_sk(&ps, &sk, &base);
    let _ = wots::ltree(&ps, &pk, &base);
    println!("profile: wots_key_us = {}", t.elapsed().as_micros());

    // One XMSS layer public key (LEAVES WOTS keys + tree).
    let t = Instant::now();
    let _ = xmss::xmss_pk(&ps, &esk, 0, 0);
    println!("profile: xmss_pk_layer_us = {}", t.elapsed().as_micros());

    // FORS sign + verify round.
    let mut idx = [0u32; hypg_ds::params::FORS_K];
    let mut k = 0u32;
    while (k as usize) < hypg_ds::params::FORS_K {
        idx[k as usize] = (k * 37 + 11) & hypg_ds::params::FORS_T_MASK;
        k += 1;
    }
    let t = Instant::now();
    let fsig = fors::fors_sign(&ps, &esk, &idx);
    let fsign_us = t.elapsed().as_micros();
    let t = Instant::now();
    let _ = fors::fors_verify(&ps, &idx, &fsig);
    println!("profile: fors_sign_us = {fsign_us} fors_verify_us = {}", t.elapsed().as_micros());
}

/// Welch's t-statistic for two samples (means, variances, lengths).
/// Returns 0.0 when either sample has zero variance (no signal measurable).
/// Harness-only `u128 as f64` conversion (timing statistics, never secrets).
#[allow(clippy::cast_precision_loss)]
fn welch_t(a: &[u128], b: &[u128]) -> f64 {
    let (na, nb) = (a.len() as f64, b.len() as f64);
    let (ma, mb) = (
        a.iter().map(|&x| x as f64).sum::<f64>() / na,
        b.iter().map(|&x| x as f64).sum::<f64>() / nb,
    );
    let (va, vb) = (
        a.iter().map(|&x| (x as f64 - ma).powi(2)).sum::<f64>() / (na - 1.0),
        b.iter().map(|&x| (x as f64 - mb).powi(2)).sum::<f64>() / (nb - 1.0),
    );
    if va == 0.0 || vb == 0.0 {
        return 0.0;
    }
    (ma - mb) / ((va / na + vb / nb).sqrt())
}

fn main() {
    let n = iters();
    let seed = [0x42u8; 32];
    let coins = [0x11u8; 32];

    // Warmup (JIT/paging, not measured).
    let (pk, sk) = keygen(&seed);
    let (ct, ss) = encaps(&pk, &coins);
    assert_eq!(ss, decaps(&sk, &ct), "round-trip must hold before bench");

    // Throughput: average per-op microseconds (integer division).
    let t = Instant::now();
    for _ in 0..n {
        let _ = keygen(&seed);
    }
    let keygen_us = t.elapsed().as_micros() / u128::from(n);

    let t = Instant::now();
    for _ in 0..n {
        let _ = encaps(&pk, &coins);
    }
    let encaps_us = t.elapsed().as_micros() / u128::from(n);

    let t = Instant::now();
    for _ in 0..n {
        let _ = decaps(&sk, &ct);
    }
    let decaps_us = t.elapsed().as_micros() / u128::from(n);

    // Timing smoke: interleaved valid/tampered decaps samples (ns each).
    let mut bad = ct;
    bad.0[0] ^= 0x01;
    let mut valid_ns: Vec<u128> = Vec::new();
    let mut tampered_ns: Vec<u128> = Vec::new();
    for _ in 0..n {
        let t = Instant::now();
        let _ = decaps(&sk, &ct);
        valid_ns.push(t.elapsed().as_nanos());
        let t = Instant::now();
        let _ = decaps(&sk, &bad);
        tampered_ns.push(t.elapsed().as_nanos());
    }
    let med_valid = median(valid_ns).max(1);
    let med_tampered = median(tampered_ns).max(1);
    // Per-mille ratio `tampered/valid * 1000` (integer, no floats).
    let ratio_pm = med_tampered.saturating_mul(1000) / med_valid;

    println!("hypg_bench iters = {n}");
    println!("sizes: pk = {} ct = {} sk = {} ss = 32 (bytes)", pk.0.len(), ct.0.len(), sk.0.len());
    println!("avg_us: keygen = {keygen_us} encaps = {encaps_us} decaps = {decaps_us}");
    println!("decaps_median_ns: valid = {med_valid} tampered = {med_tampered}");
    println!("tampered_over_valid_pm = {ratio_pm} (1000 = identical)");
    if !(500..=2000).contains(&ratio_pm) {
        println!("NOTE: timing ratio outside [500, 2000] per-mille — investigate, not a failure");
    }

    // Symm throughput over a 1 KiB message (integer averages).
    symm_bench(n);

    // Large-message throughput proof (1 MiB, fixed reps).
    big_bench();

    // DS throughput (hypertree signing; few iterations by default).
    ds_bench();

    // Optional cost breakdown (env-gated, public APIs only).
    if profile_on() {
        ds_profile();
    }

    // Welch t-test over fresh interleaved samples (A/B/A/B order damps drift).
    let tn = ttest_n();
    if tn > 0 {
        // Sweep tamper positions: c1 head/mid, c2 head/mid, last byte.
        // A position-dependent split would implicate a specific decode path.
        let spots: [(&str, usize); 5] = [
            ("c1[0]", 0),
            ("c1[320]", C1_PACKED_LEN),
            ("c2[0]", C1_VEC_PACKED_LEN),
            ("c2[80]", C1_VEC_PACKED_LEN + 80),
            ("ct[last]", CT_LEN - 1),
        ];
        for (name, pos) in spots {
            let mut bad_spot = ct;
            bad_spot.0[pos] ^= 0x01;
            let mut xs: Vec<u128> = Vec::new();
            let mut ys: Vec<u128> = Vec::new();
            for _ in 0..tn {
                let t = Instant::now();
                let _ = decaps(&sk, &ct);
                xs.push(t.elapsed().as_nanos());
                let t = Instant::now();
                let _ = decaps(&sk, &bad_spot);
                ys.push(t.elapsed().as_nanos());
            }
            let t = welch_t(&xs, &ys);
            println!("welch_t_n = {tn} spot = {name} welch_t = {t:.3}");
        }
        println!("(bar |t| > 4.5 with n >= 10000; informational only)");
    }
}
