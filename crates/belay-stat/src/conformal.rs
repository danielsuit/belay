//! Conformal guarantees (§IV.7).
//!
//! For the user who asks "how sure are you," a distribution-free answer.
//! Split conformal: with `n` calibration nonconformity scores, the threshold
//! is the `⌈(n+1)(1−α)⌉`-th smallest; the resulting prediction set has
//! **marginal coverage ≥ 1 − α** with no assumption about the model beyond
//! exchangeability. Set size is the honest cost — small = confident, large =
//! not, both useful. Exchangeability bites on a real repo (it isn't drawn from
//! the RustSec distribution); refresh calibration with triage labels (§V.5).

/// The split-conformal threshold: the `⌈(n+1)(1−α)⌉`-th smallest calibration
/// score. A new point with score ≤ threshold is in the `1 − α` prediction set.
pub fn split_conformal_threshold(cal_scores: &[f64], alpha: f64) -> f64 {
    let n = cal_scores.len();
    if n == 0 {
        return f64::INFINITY;
    }
    let mut s = cal_scores.to_vec();
    s.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let rank = (((n as f64) + 1.0) * (1.0 - alpha)).ceil() as usize;
    let idx = rank.saturating_sub(1).min(n - 1);
    s[idx]
}

/// Is a new point (with nonconformity `score`) in the `1 − α` set?
pub fn in_conformal_set(score: f64, threshold: f64) -> bool {
    score <= threshold
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn threshold_is_the_right_quantile() {
        // 100 calibration scores 1..=100; alpha=0.1 → rank ⌈101*0.9⌉=91 → 91.
        let cal: Vec<f64> = (1..=100).map(|x| x as f64).collect();
        let t = split_conformal_threshold(&cal, 0.1);
        assert_eq!(t, 91.0);
        assert!(in_conformal_set(50.0, t));
        assert!(!in_conformal_set(99.0, t));
    }

    #[test]
    fn coverage_on_exchangeable_sample() {
        // With calibration = test = uniform draws from the same pool, empirical
        // coverage of the conformal set should be ≈ 1 − α (marginally).
        let cal: Vec<f64> = (1..=200).map(|x| x as f64).collect();
        let alpha = 0.1;
        let t = split_conformal_threshold(&cal, alpha);
        // Fresh exchangeable scores 1..=200.
        let mut covered = 0;
        let test: Vec<f64> = (1..=200).map(|x| x as f64).collect();
        for s in &test {
            if in_conformal_set(*s, t) {
                covered += 1;
            }
        }
        let frac = covered as f64 / test.len() as f64;
        assert!(frac >= 1.0 - alpha - 0.05, "coverage {frac} below nominal");
    }
}
