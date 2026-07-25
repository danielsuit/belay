//! Pandora's box (Weitzman 1979) — which pass-1 candidates to pay to
//! investigate, and when to stop (§III.6).
//!
//! Pass 2 is expensive and sequential: each candidate has a calibrated value
//! distribution `V_i` (severity × P(it confirms)) and a known inspection cost
//! `c_i` (expected turns × tokens). Weitzman's index policy is *optimal*, not
//! heuristic: it fuses severity, calibrated confidence, and inspection cost
//! into one scalar and tells you when to stop paying.
//!
//! Independence is Weitzman's assumption; the correlated generalization
//! (Bayesian-network prior) is intractable in general. The practical fix — a
//! class-and-module prior updated after each confirmation, re-solving σ — is
//! applied in the engine loop, and noted as an approximation rather than
//! pretended away.

/// A candidate's value distribution: `(value, probability)` pairs.
pub type Dist = Vec<(f64, f64)>;

/// E[(V - σ)^+] — the expected excess over σ. Decreasing in σ.
fn expected_excess(dist: &Dist, sigma: f64) -> f64 {
    dist.iter()
        .map(|(v, p)| p * (v - sigma).max(0.0))
        .sum()
}

/// Reservation value σ solving `E[(V - σ)^+] = cost` by bisection on `[0, vmax]`.
pub fn reservation_value(dist: &Dist, cost: f64) -> f64 {
    if dist.is_empty() || cost <= 0.0 {
        return 0.0;
    }
    let vmax = dist.iter().map(|(v, _)| *v).fold(0.0f64, f64::max);
    if expected_excess(dist, 0.0) <= cost {
        // Investigating is never worth it at any non-negative σ; σ = 0 means
        // "only open if nothing better is available" — effectively never first.
        return 0.0;
    }
    let mut lo = 0.0f64;
    let mut hi = vmax;
    for _ in 0..100 {
        let mid = (lo + hi) / 2.0;
        let g = expected_excess(dist, mid);
        if g > cost {
            lo = mid; // excess too big → σ higher
        } else {
            hi = mid;
        }
    }
    (lo + hi) / 2.0
}

/// A pass-2 candidate: id, value distribution, inspection cost, and (once
/// investigated) a confirmed value if it panned out.
#[derive(Clone, Debug)]
pub struct Pandora {
    pub id: u32,
    pub dist: Dist,
    pub cost: f64,
    pub confirmed: Option<f64>,
}

impl Pandora {
    pub fn reservation(&self) -> f64 {
        reservation_value(&self.dist, self.cost)
    }
}

/// Order candidates by reservation value, descending (open highest-σ first).
pub fn order(candidates: &[Pandora]) -> Vec<u32> {
    let mut idx: Vec<u32> = candidates.iter().map(|c| c.id).collect();
    idx.sort_unstable_by(|&a, &b| {
        let ra = candidates.iter().find(|c| c.id == a).unwrap().reservation();
        let rb = candidates.iter().find(|c| c.id == b).unwrap().reservation();
        rb.partial_cmp(&ra).unwrap_or(std::cmp::Ordering::Equal)
    });
    idx
}

/// Weitzman stopping rule: stop when the best confirmed value ≥ the largest
/// reservation value among the unopened candidates.
pub fn should_stop(best_confirmed: f64, unopened: &[&Pandora]) -> bool {
    let max_sigma = unopened
        .iter()
        .map(|c| c.reservation())
        .fold(0.0f64, f64::max);
    best_confirmed >= max_sigma
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bernoulli(severity: f64, p: f64) -> Dist {
        vec![(severity, p), (0.0, 1.0 - p)]
    }

    #[test]
    fn reservation_matches_bernoulli_closed_form() {
        // E[(V-σ)^+] = p*(s-σ) = c  ⟹  σ = s - c/p
        let dist = bernoulli(10.0, 0.5);
        let cost = 1.0;
        let sigma = reservation_value(&dist, cost);
        let closed = 10.0 - 1.0 / 0.5; // 8.0
        assert!((sigma - closed).abs() < 1e-3, "sigma={sigma} closed={closed}");
    }

    #[test]
    fn higher_severity_or_prob_higher_sigma() {
        let low = reservation_value(&bernoulli(5.0, 0.5), 1.0);
        let high = reservation_value(&bernoulli(10.0, 0.5), 1.0);
        assert!(high > low);
        let hi_p = reservation_value(&bernoulli(10.0, 0.9), 1.0);
        assert!(hi_p > high);
    }

    #[test]
    fn order_is_descending_sigma() {
        let cands = vec![
            Pandora { id: 0, dist: bernoulli(10.0, 0.5), cost: 1.0, confirmed: None },
            Pandora { id: 1, dist: bernoulli(100.0, 0.5), cost: 1.0, confirmed: None },
            Pandora { id: 2, dist: bernoulli(2.0, 0.5), cost: 1.0, confirmed: None },
        ];
        let order = order(&cands);
        assert_eq!(order, vec![1, 0, 2]);
    }

    #[test]
    fn stop_when_confirmed_beats_remaining_sigma() {
        let cands = vec![
            Pandora { id: 0, dist: bernoulli(50.0, 0.5), cost: 1.0, confirmed: Some(50.0) },
            Pandora { id: 1, dist: bernoulli(5.0, 0.5), cost: 1.0, confirmed: None },
        ];
        let unopened: Vec<&Pandora> = cands.iter().filter(|c| c.confirmed.is_none()).collect();
        // confirmed 50 >= max σ of remaining (≈ 5 - 1/0.5 = 3)
        assert!(should_stop(50.0, &unopened));
    }
}
