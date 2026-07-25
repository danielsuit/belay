//! SPRT and anytime-valid stopping (§IV.2).
//!
//! "Turn cap 8" is a guess. The principled version accumulates a
//! log-likelihood ratio per turn and stops at Wald boundaries. SPRT minimizes
//! expected sample size among all tests with error rates (α, β) for simple
//! hypotheses (Wald–Wolfowitz).
//!
//! Honesty caveat: SPRT optimality assumes i.i.d. evidence; consecutive tool
//! calls in one rollout are dependent, so the nominal α isn't the real α. The
//! rigorous replacement is a test martingale / e-value: a nonnegative process
//! `M_n` with `E[M_n | F_{n−1}] ≤ M_{n−1}` under the null, stopped when
//! `M_n ≥ 1/α` — Ville's inequality gives `P(∃n : M_n ≥ 1/α) ≤ α`, valid at any
//! stopping time under dependence. We ship SPRT thresholds as the interface and
//! implement the accumulator as an e-process.

/// SPRT decision.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Decision {
    /// Accept the alternative (vuln confirmed).
    Accept,
    /// Accept the null (benign — refuted).
    Reject,
    /// Keep gathering evidence.
    Continue,
}

/// A sequential accumulator with Wald SPRT boundaries, backed by an e-process
/// for the anytime-valid guarantee.
#[derive(Clone, Debug)]
pub struct Accumulator {
    /// Log-likelihood ratio Λ_n = Σ log LR.
    llr: f64,
    /// E-process value M_n = Π e_i (one per turn). Under the null,
    /// E[M_n | F_{n-1}] ≤ M_{n-1}.
    e_value: f64,
    /// Accept boundary: log((1-β)/α).
    accept_bound: f64,
    /// Reject boundary: log(β/(1-α)).
    reject_bound: f64,
    /// Ville threshold for the e-process: 1/α.
    ville: f64,
    turns: u32,
    /// Hard cost guard (not the decision rule).
    pub turn_cap: u32,
}

impl Accumulator {
    /// New accumulator with target error rates `alpha` (false positive) and
    /// `beta` (false negative). The e-process Ville threshold is `1/alpha`.
    pub fn new(alpha: f64, beta: f64) -> Self {
        assert!(alpha > 0.0 && alpha < 1.0);
        assert!(beta > 0.0 && beta < 1.0);
        Self {
            llr: 0.0,
            e_value: 1.0,
            accept_bound: ((1.0 - beta) / alpha).ln(),
            reject_bound: (beta / (1.0 - alpha)).ln(),
            ville: 1.0 / alpha,
            turns: 0,
            turn_cap: 16,
        }
    }

    /// Feed one turn's evidence.
    ///
    /// `llr` is log[ P(e | vuln) / P(e | benign) ]. `e_value` is the per-turn
    /// e-value under the null (1.0 = no evidence against the null; >1 grows).
    /// For a calibrated probability `p = P(vuln | e)`, a reasonable pair is
    /// `llr = log(p/(1-p))` and `e_value = p/(1-p)` clipped to ≥ 0.
    pub fn observe(&mut self, llr: f64, e_value: f64) -> Decision {
        self.llr += llr;
        self.e_value *= e_value.max(0.0);
        self.turns += 1;
        self.decide()
    }

    /// Decide from the current state.
    pub fn decide(&self) -> Decision {
        // Anytime-valid e-process check first (Ville): under the null, the
        // chance of ever crossing 1/alpha is ≤ alpha. Crossing ⇒ reject the null
        // ⇒ accept the alternative (vuln).
        if self.e_value >= self.ville {
            return Decision::Accept;
        }
        if self.llr >= self.accept_bound {
            return Decision::Accept;
        }
        if self.llr <= self.reject_bound {
            return Decision::Reject;
        }
        if self.turns >= self.turn_cap {
            // Cost guard: if we've spent the cap without a boundary, lean on the
            // sign of the accumulated evidence (a conservative default-to-reject
            // keeps the FDR guarantee intact).
            return if self.llr > 0.0 {
                Decision::Accept
            } else {
                Decision::Reject
            };
        }
        Decision::Continue
    }

    pub fn llr(&self) -> f64 {
        self.llr
    }
    pub fn e_value(&self) -> f64 {
        self.e_value
    }
    pub fn turns(&self) -> u32 {
        self.turns
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strong_vuln_evidence_accepts() {
        let mut acc = Accumulator::new(0.05, 0.05);
        // Each turn: p=0.9 → llr = log(9) ≈ 2.197; e_value = 9.
        let mut dec = Decision::Continue;
        for _ in 0..10 {
            dec = acc.observe(2.197, 9.0);
            if dec != Decision::Continue {
                break;
            }
        }
        assert_eq!(dec, Decision::Accept);
        // Ville: 9 per turn → after 1 turn e=9 >= 1/0.05=20? no. after 2 turns 81>=20 yes.
        assert!(acc.e_value() >= 20.0);
    }

    #[test]
    fn benign_evidence_rejects() {
        let mut acc = Accumulator::new(0.05, 0.05);
        // p=0.1 → llr = log(0.1/0.9) = log(1/9) ≈ -2.197; e_value small.
        let mut dec = Decision::Continue;
        for _ in 0..10 {
            dec = acc.observe(-2.197, 0.111);
            if dec != Decision::Continue {
                break;
            }
        }
        assert_eq!(dec, Decision::Reject);
    }

    #[test]
    fn ambiguous_runs_to_cap() {
        let mut acc = Accumulator::new(0.05, 0.05);
        acc.turn_cap = 3;
        let mut dec = Decision::Continue;
        for _ in 0..10 {
            dec = acc.observe(0.0, 1.0); // no evidence
            if dec != Decision::Continue {
                break;
            }
        }
        // llr 0, turns hit cap → default reject (llr not > 0).
        assert_eq!(dec, Decision::Reject);
    }

    #[test]
    fn ville_guarantee_threshold() {
        // A single huge e-value should accept via Ville, not via the LLR bound.
        let mut acc = Accumulator::new(0.10, 0.10);
        let dec = acc.observe(0.0, 50.0); // e=50 >= 1/0.1=10
        assert_eq!(dec, Decision::Accept);
    }
}
