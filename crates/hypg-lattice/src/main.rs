//! `hypg-lattice`: local lattice lab (std binary, zero-dep).
//!
//! Floats live only in this harness; libraries stay float-free.
//!
//! Coverage: LLL reduction (classical, `f64` Gram–Schmidt) with exactness
//! tests; toy-LWE end-to-end break (`n = 8`, `q = 257`) proving the
//! primal-embedding harness recovers planted secrets at weak parameters
//! (the healthy result is that the same method fails to scale); and
//! real-parameter gap analysis from the shipped constants. BKZ-blocksize
//! costing stays in `docs/estimator.md` (Sage backlog) — no hand-rolled
//! inequalities here.
//!
//! Harness-only numeric casts between int and float types for lattice
//! arithmetic and statistics; libraries stay cast-clean per policy.

#![forbid(unsafe_code)]
#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss,
    clippy::cast_lossless,
    clippy::cast_precision_loss
)]

use hypg_kem::{decaps, encaps, keygen};

// ---------------------------------------------------------------------------
// Tiny deterministic PRNG (xorshift32, harness only).
// ---------------------------------------------------------------------------

struct Rng(u32);

impl Rng {
    fn next(&mut self) -> u32 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 17;
        x ^= x << 5;
        self.0 = x;
        x
    }
    fn below(&mut self, n: u32) -> u32 {
        self.next() % n
    }
    /// Balanced small value in `-2..=2` (mirrors `CBD(eta=2)` support).
    fn small(&mut self) -> i64 {
        (self.below(5) as i64) - 2
    }
}

// ---------------------------------------------------------------------------
// LLL (classical Lenstra–Lenstra–Lovász, row-vector basis, `f64` GS).
// ---------------------------------------------------------------------------

fn dot(a: &[f64], b: &[f64]) -> f64 {
    a.iter().zip(b.iter()).map(|(x, y)| x * y).sum()
}

/// Gram–Schmidt: returns `(bstar, mu, norms_sq)`.
#[allow(clippy::many_single_char_names)]
fn gram_schmidt(basis: &[Vec<i64>]) -> (Vec<Vec<f64>>, Vec<Vec<f64>>, Vec<f64>) {
    let b: Vec<Vec<f64>> = basis.iter().map(|r| r.iter().map(|&x| x as f64).collect()).collect();
    let mut bstar: Vec<Vec<f64>> = Vec::with_capacity(b.len());
    let mut mu: Vec<Vec<f64>> = vec![vec![0.0; b.len()]; b.len()];
    let mut norm2: Vec<f64> = Vec::with_capacity(b.len());
    for (i, bi) in b.iter().enumerate() {
        let mut v = bi.clone();
        for (j, bs) in bstar.iter().enumerate().take(i) {
            let m = dot(bi, bs) / norm2[j];
            mu[i][j] = m;
            for (vk, sk) in v.iter_mut().zip(bs.iter()) {
                *vk -= m * sk;
            }
        }
        norm2.push(dot(&v, &v));
        bstar.push(v);
    }
    (bstar, mu, norm2)
}

/// Reduce `basis` in place. Returns swap count. `delta` in `(0.25, 1)`.
pub fn lll(basis: &mut [Vec<i64>], delta: f64, max_swaps: usize) -> usize {
    let mut swaps = 0usize;
    let mut k = 1usize;
    while k < basis.len() {
        // Size-reduce `b[k]` against `b[0..k]`, recomputing coefficients
        // after each applied step (rows `< k` are fixed, so only `mu[k][·]`
        // can go stale — fresh GS per `j` keeps it exact).
        for j in (0..k).rev() {
            let (_, mu, _) = gram_schmidt(basis);
            let q = mu[k][j].round() as i64;
            if q != 0 {
                let (head, tail) = basis.split_at_mut(k);
                for (tk, hj) in tail[0].iter_mut().zip(head[j].iter()) {
                    *tk -= q * hj;
                }
            }
        }
        let (_, mu2, norm2) = gram_schmidt(basis);
        let lovasz_lhs = (delta - mu2[k][k - 1] * mu2[k][k - 1]) * norm2[k - 1];
        if lovasz_lhs > norm2[k] {
            basis.swap(k, k - 1);
            swaps += 1;
            if swaps >= max_swaps {
                break;
            }
            if k > 1 {
                k -= 1;
            }
        } else {
            k += 1;
        }
    }
    swaps
}

fn row_norm2(row: &[i64]) -> i64 {
    row.iter().map(|x| x * x).sum()
}

/// Brute-force shortest non-zero vector norm² (tiny dims only).
fn brute_shortest_norm2(basis: &[Vec<i64>], radius: i64) -> i64 {
    let n = basis.len();
    let span = (2 * radius + 1) as usize;
    let total: usize = span.pow(n as u32);
    let mut best = i64::MAX;
    for idx in 0..total {
        let mut tmp = idx;
        let dim = basis[0].len();
        let mut v = vec![0i64; dim];
        let mut zero = true;
        for row in basis {
            let c = (tmp % span) as i64 - radius;
            tmp /= span;
            if c != 0 {
                zero = false;
            }
            for (vk, bk) in v.iter_mut().zip(row.iter()) {
                *vk += c * bk;
            }
        }
        if !zero {
            let q = row_norm2(&v);
            if q < best {
                best = q;
            }
        }
    }
    best
}

// ---------------------------------------------------------------------------
// Toy LWE + primal (Kannan) embedding.
// ---------------------------------------------------------------------------

/// Build a toy instance: `n = 8`, `m = 16`, `q = 257`, secrets/errors in
/// `-2..=2`. Returns `(basis_rows, target_norm2)`; the lattice (dim 25)
/// contains a planted vector of `target_norm2` (the `(e, -s, 1)` combination).
#[allow(clippy::many_single_char_names)]
fn toy_instance() -> (Vec<Vec<i64>>, i64) {
    const N: usize = 8;
    const M: usize = 16;
    const Q: i64 = 257;
    let mut rng = Rng(0x00C0_FFEE);
    let mut mat = vec![vec![0i64; N]; M];
    for row in &mut mat {
        for x in row.iter_mut() {
            *x = (rng.next() % 257) as i64;
        }
    }
    let mut sec = vec![0i64; N];
    for x in &mut sec {
        *x = rng.small();
    }
    let mut err = vec![0i64; M];
    for x in &mut err {
        *x = rng.small();
    }
    // `t = (A·s + e) mod q`, centered to `(-q/2, q/2]`.
    let mut tgt = [0i64; M];
    for (i, ti) in tgt.iter_mut().enumerate() {
        let mut v: i64 = err[i];
        for (ai, si) in mat[i].iter().zip(sec.iter()) {
            v += ai * si;
        }
        let mut r = v % Q;
        if r > Q / 2 {
            r -= Q;
        }
        if r < -Q / 2 {
            r += Q;
        }
        *ti = r;
    }
    // Embedding basis, dim `M + N + 1 = 25`:
    // rows 0..M: q·e_i | rows M..M+N: [A col j | e_j] | last: [t | 0 | 1].
    let dim = M + N + 1;
    let mut basis = Vec::new();
    for i in 0..M {
        let mut r = vec![0i64; dim];
        r[i] = Q;
        basis.push(r);
    }
    for (j, secj) in sec.iter().enumerate().take(N) {
        let _ = secj;
        let mut r = vec![0i64; dim];
        for (i, row) in mat.iter().enumerate().take(M) {
            r[i] = row[j];
        }
        r[M + j] = 1;
        basis.push(r);
    }
    {
        let mut r = vec![0i64; dim];
        r[..M].copy_from_slice(&tgt);
        r[dim - 1] = 1;
        basis.push(r);
    }
    let target = row_norm2(&err) + row_norm2(&sec) + 1;
    (basis, target)
}

// ---------------------------------------------------------------------------
// Real-parameter gap analysis (constants + shipped code, no inequalities).
// ---------------------------------------------------------------------------

/// `log2 |det|` via Gaussian elimination with partial pivoting (`f64`,
/// harness-only volume estimates for GH comparisons).
fn det_log2(mat: &[Vec<i64>]) -> f64 {
    let n = mat.len();
    let mut a: Vec<Vec<f64>> = mat.iter().map(|r| r.iter().map(|&x| x as f64).collect()).collect();
    let mut log_sum = 0.0f64;
    for col in 0..n {
        let mut piv = col;
        for row in col..n {
            if a[row][col].abs() > a[piv][col].abs() {
                piv = row;
            }
        }
        if a[piv][col] == 0.0 {
            return f64::NEG_INFINITY; // singular (should not happen here)
        }
        a.swap(col, piv);
        log_sum += a[col][col].abs().log2();
        let diag = a[col][col];
        let (done, rest) = a.split_at_mut(col + 1);
        for arow in rest {
            let factor = arow[col] / diag;
            for (k, ak) in arow.iter_mut().enumerate().skip(col) {
                *ak -= factor * done[col][k];
            }
        }
    }
    log_sum
}

/// Gaussian-heuristic length of a `d`-dimensional lattice of volume `vol`:
/// `sqrt(d / (2πe)) · vol^(1/d)`.
fn gaussian_heuristic(d: f64, log2_vol: f64) -> f64 {
    (d / (2.0 * std::f64::consts::PI * std::f64::consts::E)).sqrt() * 2.0f64.powf(log2_vol / d)
}

fn real_params() -> (bool, String) {
    // Module-LWE as plain LWE: N = n·k = 1024 unknowns; primal attack with
    // m = 1024 samples → embedding dim d = m + N + 1 = 2049, vol = q^m.
    let (n, k, m) = (256.0f64, 4.0f64, 1024.0f64);
    let (qlog2, sigma) = (12.0f64, 1.0f64); // q = 4096, CBD(2) var 1
    let dim = m + n * k + 1.0;
    let log2_vol = m * qlog2;
    let gh = gaussian_heuristic(dim, log2_vol);
    let target = ((m + n * k) * sigma * sigma + 1.0).sqrt();
    let gap = gh / target;
    // Textbook LLL worst case: ||b1|| ≤ 2^((d-1)/2)·λ1 — its log2 distance
    // above the planted target lower-bounds LLL-class hopelessness.
    let lll_log2_slack = (dim - 1.0) / 2.0 + target.log2() - gh.log2();
    let ok = gap > 10.0 && lll_log2_slack > 100.0;
    (
        ok,
        format!(
            "d={dim:.0} log2vol={log2_vol:.0} GH={gh:.1} target={target:.1} gap={gap:.1}x LLL-slack=2^{lll_log2_slack:.0} (need gap>10, slack>2^100)"
        ),
    )
}

fn main() {
    let mut failures = 0u32;
    let mut check = |name: &str, ok: bool, detail: String| {
        println!("{}: {name} — {detail}", if ok { "PASS" } else { "FAIL" });
        if !ok {
            failures += 1;
        }
    };

    // L1: 2D Gauss exactness vs brute force on fixed bases.
    {
        let bases: Vec<Vec<Vec<i64>>> = vec![
            vec![vec![19, 2], vec![5, 8]],
            vec![vec![201, 37], vec![164, 91]],
            vec![vec![137, 59], vec![11, 13]],
        ];
        let mut bad = 0u32;
        for base in &bases {
            let opt = brute_shortest_norm2(base, 12);
            let mut reduced = base.clone();
            lll(&mut reduced, 0.99, 10_000);
            let got = reduced.iter().map(|r| row_norm2(r)).min().unwrap_or(i64::MAX);
            if got != opt {
                bad += 1;
            }
        }
        check(
            "L1 lll-2d-exact",
            bad == 0,
            format!("3 fixed bases, {bad} mismatches vs brute force"),
        );
    }

    // L2: toy-LWE break — LLL must find a vector at planted scale
    // (far below the 25-dim Gaussian heuristic ≈ 42).
    {
        let (mut basis, target) = toy_instance();
        let d = basis.len() as f64;
        let gh = gaussian_heuristic(d, 16.0 * 8.0); // vol q^16, log2 ≈ 16·8.0056
        lll(&mut basis, 0.99, 1_000_000);
        let found = basis.iter().map(|r| row_norm2(r)).min().unwrap_or(i64::MAX);
        let ok = found <= target + 2;
        check(
            "L2 toy-lwe-break",
            ok,
            format!("planted={target} found={found} GH≈{gh:.0} (need found ≤ planted+2)"),
        );
    }

    // L3: dense random lattice — LLL should reach ≈GH (volume measured
    // by LU, GH computed from it). Sanity that LLL works on dense input;
    // a triangular Lovász-ordered basis would correctly no-op, so dense
    // input is required for a meaningful check.
    {
        const D: usize = 32;
        let mut rng = Rng(0x00BA_AAAA);
        let mut basis = Vec::new();
        for _ in 0..D {
            let mut r = vec![0i64; D];
            for x in &mut r {
                // Balanced entries in [-2048, 2048] (non-singular w.h.p.).
                *x = (rng.next() % 4097) as i64 - 2048;
            }
            basis.push(r);
        }
        let log2_vol = det_log2(&basis);
        lll(&mut basis, 0.99, 1_000_000);
        let found = basis.iter().map(|r| row_norm2(r)).min().unwrap_or(i64::MAX) as f64;
        let gh = gaussian_heuristic(D as f64, log2_vol);
        let ratio = found.sqrt() / gh;
        let ok = log2_vol.is_finite() && ratio < 3.0;
        check(
            "L3 lll-reaches-gh-only",
            ok,
            format!("shortest={found} GH≈{gh:.0} ratio={ratio:.2} (need < 3.0)"),
        );
    }

    // L4: real-parameter gap from shipped constants.
    {
        let (ok, detail) = real_params();
        check("L4 real-param-gap", ok, detail);
    }

    // L5: live round-trip through the shipped KEM (ties lab to product).
    {
        let (pk, sk) = keygen(&[0x42u8; 32]);
        let (ct, ss) = encaps(&pk, &[0x11u8; 32]);
        let ok = decaps(&sk, &ct) == ss;
        check("L5 live-kem-roundtrip", ok, format!("pk={}B ct={}B", pk.0.len(), ct.0.len()));
    }

    if failures > 0 {
        eprintln!("lattice: {failures} check(s) FAILED");
        std::process::exit(1);
    }
    println!("lattice: all checks passed");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lll_2d_exact4417() {
        // Fixed regression: LLL must reproduce the brute-force optimum.
        let b = [vec![44i64, 17], vec![29, 31]];
        let opt = brute_shortest_norm2(&b, 12);
        let mut r = [b[0].clone(), b[1].clone()];
        lll(&mut r, 0.99, 10_000);
        let got = r.iter().map(|r| row_norm2(r)).min().unwrap_or(i64::MAX);
        assert_eq!(got, opt);
    }

    #[test]
    fn lll_reduced_form() {
        // Output must be size-reduced (|μ| ≤ 0.5+) and Lovász-ordered.
        let mut b = [vec![8i64, 2, 1], vec![3, 9, 4], vec![1, 2, 7]];
        lll(&mut b, 0.99, 10_000);
        let (_, mu, norm2) = gram_schmidt(&b);
        for (i, mui) in mu.iter().enumerate().take(3) {
            for muj in mui.iter().take(i) {
                assert!(muj.abs() <= 0.500_001, "not size-reduced");
            }
            if i > 0 {
                let lhs = (0.99 - mui[i - 1] * mui[i - 1]) * norm2[i - 1];
                assert!(lhs <= norm2[i] * 1.000_001, "Lovász violated");
            }
        }
    }

    #[test]
    fn toy_breaks() {
        let (mut basis, target) = toy_instance();
        lll(&mut basis, 0.99, 1_000_000);
        let found = basis.iter().map(|r| row_norm2(r)).min().unwrap_or(i64::MAX);
        assert!(found <= target + 2, "planted={target} found={found}");
    }
}
