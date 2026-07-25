//! False-discovery-rate control (§IV.5, §IV.6).
//!
//! A 51k-LOC scan runs ~300 chain-level tests. At a per-test FP rate of 5%
//! that is 15 false findings even if the tool works perfectly. Per-test control
//! is the wrong guarantee; control the *false discovery rate* — the expected
//! fraction of reported findings that are wrong.
//!
//! - **BH** (Benjamini–Hochberg): FDR ≤ q under independence / PRDS.
//! - **e-BH** (Wang & Ramdas): feed the §IV.2 e-values directly; FDR ≤ q under
//!   *arbitrary dependence*, no log penalty. The natural choice here.
//! - **Alpha-investing** (Foster–Stine): online FDR over an infinite stream of
//!   tests — a scanner producing true findings earns the right to be more
//!   aggressive; a clean streak becomes conservative.

/// Benjamini–Hochberg: reject hypotheses whose p-values pass the step-up
/// threshold. Returns the indices (into the input) of rejected hypotheses.
pub fn benjamini_hochberg(p_values: &[f64], q: f64) -> Vec<usize> {
    let m = p_values.len();
    if m == 0 {
        return Vec::new();
    }
    let mut order: Vec<usize> = (0..m).collect();
    order.sort_by(|&a, &b| p_values[a].partial_cmp(&p_values[b]).unwrap_or(std::cmp::Ordering::Equal));
    // k* = max { k : p_(k) <= k*q/m }
    let mut k_star = 0;
    for (rank, &idx) in order.iter().enumerate() {
        let k = rank + 1;
        if p_values[idx] <= (k as f64) * q / m as f64 {
            k_star = k;
        }
    }
    order.into_iter().take(k_star).collect()
}

/// e-BH (Wang & Ramdas 2022): reject using e-values. Sort e-values descending;
/// `k* = max { k : e_(k) >= m/(q*k) }`; reject the k* largest. FDR ≤ q under
/// arbitrary dependence. Returns indices into the input.
pub fn e_bh(e_values: &[f64], q: f64) -> Vec<usize> {
    let m = e_values.len();
    if m == 0 || q <= 0.0 {
        return Vec::new();
    }
    let mut order: Vec<usize> = (0..m).collect();
    order.sort_by(|&a, &b| e_values[b].partial_cmp(&e_values[a]).unwrap_or(std::cmp::Ordering::Equal));
    let threshold = m as f64 / q;
    let mut k_star = 0;
    for (rank, &idx) in order.iter().enumerate() {
        let k = (rank + 1) as f64;
        if e_values[idx] >= threshold / k {
            k_star = rank + 1;
        }
    }
    order.into_iter().take(k_star).collect()
}

/// Online FDR via alpha-investing (Foster–Stine). Wealth starts at `alpha` and
/// is spent on tests; each rejection earns `alpha` back, so a productive
/// scanner becomes more aggressive and a clean streak becomes conservative.
/// Wealth never goes negative.
pub struct AlphaInvesting {
    wealth: f64,
    alpha: f64,
    /// Geometric spend schedule: gamma_t = alpha*(1-r)*r^(t-1), sums to alpha.
    r: f64,
    t: usize,
}

impl AlphaInvesting {
    pub fn new(alpha: f64) -> Self {
        Self { wealth: alpha, alpha, r: 0.5, t: 0 }
    }

    /// Spend-schedule value for step `t` (sums to `alpha` over the stream).
    fn gamma(&self, t: usize) -> f64 {
        self.alpha * (1.0 - self.r) * self.r.powi((t as i32) - 1)
    }

    /// Run one test. Returns whether the hypothesis at p ≤ α_t was rejected.
    pub fn test(&mut self, p: f64) -> bool {
        self.t += 1;
        let gamma = self.gamma(self.t);
        let spend = gamma.min(self.wealth).max(0.0);
        let reject = p <= spend;
        self.wealth -= spend;
        if reject {
            self.wealth += self.alpha;
        }
        reject
    }

    pub fn wealth(&self) -> f64 {
        self.wealth
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bh_rejects_small_pvalues() {
        let p = vec![0.001, 0.04, 0.03, 0.6, 0.8];
        let rej = benjamini_hochberg(&p, 0.1);
        // The first three are small; 0.6/0.8 are not.
        let mut sorted = rej.clone();
        sorted.sort();
        assert!(sorted.contains(&0));
        assert!(sorted.contains(&2)); // 0.03
        assert!(!sorted.contains(&4)); // 0.8
    }

    #[test]
    fn bh_rejects_none_when_all_large() {
        let p = vec![0.5, 0.6, 0.7];
        assert!(benjamini_hochberg(&p, 0.1).is_empty());
    }

    #[test]
    fn e_bh_rejects_large_evalues() {
        // e-values: large = strong evidence against null. With m=4, q=0.1, a
        // single rejection needs e >= m/q = 40.
        let e = vec![0.1, 50.0, 5.0, 0.5];
        let rej = e_bh(&e, 0.1);
        let mut sorted = rej.clone();
        sorted.sort();
        assert!(sorted.contains(&1)); // 50.0 clears the k=1 threshold (40)
        assert!(!sorted.contains(&0)); // 0.1
        assert!(!sorted.contains(&2)); // 5.0 < 20 (k=2 threshold)
    }

    #[test]
    fn alpha_investing_wealth_never_negative() {
        let mut inv = AlphaInvesting::new(0.1);
        // A mix: some tiny p (reject), some large (no reject).
        let ps = [0.001, 0.9, 0.001, 0.9, 0.001, 0.9, 0.001];
        for p in ps {
            inv.test(p);
            assert!(inv.wealth() >= -1e-12, "wealth went negative: {}", inv.wealth());
        }
    }

    #[test]
    fn alpha_investing_rejections_grow_wealth() {
        let mut inv = AlphaInvesting::new(0.1);
        let start = inv.wealth();
        for _ in 0..5 {
            inv.test(0.0001); // always reject
        }
        assert!(inv.wealth() > start, "rejections should grow wealth");
    }
}
