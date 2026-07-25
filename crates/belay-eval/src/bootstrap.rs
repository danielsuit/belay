//! Paired bootstrap CI and McNemar's test (§VI.5).
//!
//! **Never accept a prompt change whose bootstrap CI on Δdetection includes
//! zero.** Paired-by-advisory resampling with common random numbers (same seed
//! across variants) reduces variance on the *difference*.

/// Paired bootstrap CI on `mean(a) - mean(b)`. Returns `(point_estimate, lo,
/// hi)` at 95%. Deterministic given `seed` (no `rand` dependency).
pub fn paired_bootstrap_ci(a: &[bool], b: &[bool], n_boot: usize, seed: u64) -> (f64, f64, f64) {
    assert_eq!(a.len(), b.len());
    let n = a.len();
    if n == 0 {
        return (0.0, 0.0, 0.0);
    }
    let mean = |xs: &[bool]| xs.iter().filter(|&&x| x).count() as f64 / xs.len() as f64;
    let point = mean(a) - mean(b);
    let mut rng = Rng::new(seed);
    let mut deltas = Vec::with_capacity(n_boot);
    for _ in 0..n_boot {
        let mut ca = 0usize;
        let mut cb = 0usize;
        for _ in 0..n {
            let i = rng.next() as usize % n;
            if a[i] {
                ca += 1;
            }
            if b[i] {
                cb += 1;
            }
        }
        deltas.push(ca as f64 / n as f64 - cb as f64 / n as f64);
    }
    deltas.sort_by(|x, y| x.partial_cmp(y).unwrap_or(std::cmp::Ordering::Equal));
    let lo = quantile(&deltas, 0.025);
    let hi = quantile(&deltas, 0.975);
    (point, lo, hi)
}

fn quantile(sorted: &[f64], q: f64) -> f64 {
    if sorted.is_empty() {
        return 0.0;
    }
    let idx = ((sorted.len() as f64 - 1.0) * q).round() as usize;
    sorted[idx.min(sorted.len() - 1)]
}

/// McNemar's test on paired binary outcomes. Returns `(statistic, p_value)`.
/// p-value uses the χ²₁ survival function (erfc(√(x/2))).
pub fn mcnemar(a: &[bool], b: &[bool]) -> (f64, f64) {
    assert_eq!(a.len(), b.len());
    let mut b01 = 0usize; // a true, b false
    let mut b10 = 0usize; // a false, b true
    for (x, y) in a.iter().zip(b) {
        if *x && !*y {
            b01 += 1;
        } else if !*x && *y {
            b10 += 1;
        }
    }
    let disc = b01 + b10;
    if disc == 0 {
        return (0.0, 1.0);
    }
    // With continuity correction.
    let stat = ((b01 as f64 - b10 as f64).abs() - 1.0).max(0.0).powi(2) / disc as f64;
    let p = erfc((stat / 2.0).sqrt());
    (stat, p)
}

fn erfc(x: f64) -> f64 {
    // Abramowitz & Stegun 7.1.26 (Horner form).
    let z = x.abs();
    let p = 0.3275911;
    let (a1, a2, a3, a4, a5) = (
        0.254829592, -0.284496736, 1.421413741, -1.453152027, 1.061405429,
    );
    let t = 1.0 / (1.0 + p * z);
    let poly = a1 + t * (a2 + t * (a3 + t * (a4 + t * a5)));
    let tau = t * poly * (-z * z).exp();
    if x >= 0.0 { tau } else { 2.0 - tau }
}

struct Rng {
    state: u64,
}
impl Rng {
    fn new(seed: u64) -> Self {
        Self { state: seed.wrapping_add(0x9E3779B97F4A7C15) }
    }
    fn next(&mut self) -> u64 {
        // splitmix64
        self.state = self.state.wrapping_add(0x9E3779B97F4A7C15);
        let mut z = self.state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58476D1CE4E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D049BB133111EB);
        z ^ (z >> 31)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identical_variants_have_zero_delta() {
        let a = vec![true, false, true, true, false, true, false, false, true, true];
        let (point, lo, hi) = paired_bootstrap_ci(&a, &a, 1000, 42);
        assert!(point.abs() < 1e-9);
        assert!(lo.abs() < 1e-9 && hi.abs() < 1e-9);
    }

    #[test]
    fn clearly_better_variant_has_positive_ci() {
        // a detects everything; b detects nothing.
        let a = vec![true; 50];
        let b = vec![false; 50];
        let (point, lo, hi) = paired_bootstrap_ci(&a, &b, 2000, 7);
        assert!(point > 0.99);
        assert!(lo > 0.0, "CI lower should be positive: {lo}");
        assert!(hi <= 1.0 + 1e-6);
    }

    #[test]
    fn mcnemar_flags_disagreement() {
        // a correct on many where b wrong, and never vice versa.
        let mut a = Vec::new();
        let mut b = Vec::new();
        for _ in 0..15 {
            a.push(true);
            b.push(false);
        }
        for _ in 0..30 {
            a.push(true);
            b.push(true);
        }
        let (stat, p) = mcnemar(&a, &b);
        assert!(stat > 0.0);
        assert!(p < 0.01, "strong disagreement should be significant: p={p}");
    }

    #[test]
    fn mcnemar_no_disagreement_is_nonsignificant() {
        let a = vec![true, false, true, false];
        let b = a.clone();
        let (_stat, p) = mcnemar(&a, &b);
        assert!((p - 1.0).abs() < 1e-9);
    }
}
