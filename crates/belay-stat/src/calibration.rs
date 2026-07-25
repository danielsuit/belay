//! Calibration (§IV.1).
//!
//! Raw model confidence is not a probability. Everything downstream — SPRT
//! thresholds, Pandora σ, FDR p-values — requires `P(vuln | evidence)` to mean
//! what it says. We fit a calibrator per (model, rubric) on labeled data and
//! refuse to run FDR control with a missing or stale one.

/// Platt scaling: `p = σ(a·s + b)`, two parameters fit by logistic regression
/// on `(score, label)` pairs. Works on small calibration sets.
#[derive(Clone, Debug)]
pub struct Platt { pub a: f64, pub b: f64 }

impl Platt {
    /// Fit by gradient descent on the logistic log-loss. `scores`/`labels` must
    /// be the same length; labels are 0.0 or 1.0.
    pub fn fit(scores: &[f64], labels: &[f64], iters: usize, lr: f64) -> Self {
        let mut a = 0.0;
        let mut b = 0.0;
        let n = scores.len() as f64;
        for _ in 0..iters {
            let mut ga = 0.0;
            let mut gb = 0.0;
            for (s, &y) in scores.iter().zip(labels) {
                let z = a * s + b;
                let p = sigmoid(z);
                let d = p - y;
                ga += d * s;
                gb += d;
            }
            a -= lr * ga / n;
            b -= lr * gb / n;
        }
        Platt { a, b }
    }

    pub fn predict(&self, score: f64) -> f64 {
        sigmoid(self.a * score + self.b)
    }
}

fn sigmoid(z: f64) -> f64 {
    if z >= 0.0 {
        1.0 / (1.0 + (-z).exp())
    } else {
        z.exp() / (1.0 + z.exp())
    }
}

/// Isotonic regression via PAVA (pool-adjacent-violators), O(n). Returns the
/// stepwise monotone fit over the sorted-by-score input. `pairs` need not be
/// pre-sorted; we sort by score first.
#[derive(Clone, Debug)]
pub struct Isotonic {
    /// (score, fitted_prob) breakpoints, sorted by score, monotone non-decreasing.
    pub steps: Vec<(f64, f64)>,
}

impl Isotonic {
    pub fn fit(scores: &[f64], labels: &[f64]) -> Self {
        // Sort by score (stable), then run PAVA over the sorted labels. Each
        // point has weight 1, so a pool's weight equals its point count.
        let mut order: Vec<usize> = (0..scores.len()).collect();
        order.sort_by(|&a, &b| scores[a].partial_cmp(&scores[b]).unwrap_or(std::cmp::Ordering::Equal));
        let sorted_scores: Vec<f64> = order.iter().map(|&i| scores[i]).collect();
        let sorted_labels: Vec<f64> = order.iter().map(|&i| labels[i]).collect();

        // PAVA via a stack of (mean, weight). Merge when the new point violates
        // monotonicity (pool mean < previous pool mean).
        let mut pools: Vec<(f64, f64)> = Vec::new(); // (mean, weight)
        for &y in &sorted_labels {
            let mut v = y;
            let mut w = 1.0;
            while let Some(&(pv, pw)) = pools.last() {
                if pv > v {
                    let wsum = pw + w;
                    v = (pv * pw + v * w) / wsum;
                    w = wsum;
                    pools.pop();
                } else {
                    break;
                }
            }
            pools.push((v, w));
        }

        // Expand pools back to one fitted value per sorted point, then collapse
        // consecutive equal fits into step breakpoints.
        let mut fitted: Vec<f64> = Vec::with_capacity(sorted_scores.len());
        for (v, w) in &pools {
            let count = w.round() as usize;
            for _ in 0..count {
                fitted.push(*v);
            }
        }
        let mut steps = Vec::with_capacity(fitted.len());
        for i in 0..fitted.len() {
            steps.push((sorted_scores[i], fitted[i]));
        }
        steps.dedup_by(|a, b| (a.1 - b.1).abs() < 1e-12);
        Isotonic { steps }
    }

    pub fn predict(&self, score: f64) -> f64 {
        // Linear interpolation between breakpoints; clamp at the ends.
        if self.steps.is_empty() {
            return 0.5;
        }
        if score <= self.steps[0].0 {
            return self.steps[0].1;
        }
        if score >= self.steps[self.steps.len() - 1].0 {
            return self.steps[self.steps.len() - 1].1;
        }
        let i = self
            .steps
            .partition_point(|(s, _)| *s < score)
            .max(1);
        let (s0, v0) = self.steps[i - 1];
        let (s1, v1) = self.steps[i];
        if s1 == s0 {
            v1
        } else {
            let t = (score - s0) / (s1 - s0);
            v0 + t * (v1 - v0)
        }
    }
}

/// Expected Calibration Error: 10 bins, `ECE = Σ_b (n_b/N) |acc_b - conf_b|`.
pub fn ece(scores: &[f64], labels: &[f64], bins: usize) -> f64 {
    if scores.is_empty() {
        return 0.0;
    }
    let n = scores.len() as f64;
    let mut acc = vec![0usize; bins];
    let mut cnt = vec![0usize; bins];
    let mut conf = vec![0.0f64; bins];
    for (s, &y) in scores.iter().zip(labels) {
        let b = ((*s) * bins as f64).floor() as usize;
        let b = b.min(bins - 1);
        cnt[b] += 1;
        conf[b] += s;
        if y >= 0.5 {
            acc[b] += 1;
        }
    }
    let mut e = 0.0;
    for b in 0..bins {
        if cnt[b] == 0 {
            continue;
        }
        let avg_conf = conf[b] / cnt[b] as f64;
        let avg_acc = acc[b] as f64 / cnt[b] as f64;
        e += (cnt[b] as f64 / n) * (avg_conf - avg_acc).abs();
    }
    e
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn platt_maps_scores_toward_labels() {
        let scores = vec![0.1, 0.2, 0.8, 0.9];
        let labels = vec![0.0, 0.0, 1.0, 1.0];
        let platt = Platt::fit(&scores, &labels, 2000, 1.0);
        // Higher score → higher calibrated prob.
        assert!(platt.predict(0.9) > platt.predict(0.1));
        assert!((0.0..=1.0).contains(&platt.predict(0.5)));
    }

    #[test]
    fn isotonic_is_monotone() {
        let scores = vec![0.0, 0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9];
        let labels = vec![0.0, 0.0, 1.0, 0.0, 1.0, 1.0, 0.0, 1.0, 1.0, 1.0];
        let iso = Isotonic::fit(&scores, &labels);
        let p0 = iso.predict(0.05);
        let p1 = iso.predict(0.85);
        // Monotone non-decreasing (isotonic).
        assert!(p1 >= p0 - 1e-9);
        // All predictions in [0,1].
        for &s in &scores {
            let p = iso.predict(s);
            assert!((0.0..=1.0).contains(&p), "p={p} for s={s}");
        }
    }

    #[test]
    fn ece_zero_for_perfect_calibration() {
        // confidence == accuracy in each bin → ECE 0.
        let scores = vec![0.5; 4];
        let labels = vec![1.0, 0.0, 1.0, 0.0];
        let e = ece(&scores, &labels, 1);
        assert!((e - 0.0).abs() < 1e-9);
    }
}
