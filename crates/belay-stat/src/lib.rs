//! belay-stat: the statistical decision layer (§IV).
//!
//! Calibration (§IV.1), SPRT/e-process stopping (the accumulator lives in
//! belay-engine), FDR control (§IV.5) and online FDR (§IV.6), conformal
//! guarantees (§IV.7), near-duplicate collapse (§IV.8), and content-defined
//! fingerprints (§IV.9).

pub mod calibration;
pub mod conformal;
pub mod dedup;
pub mod fdr;
pub mod fingerprint;

pub use calibration::{ece, Isotonic, Platt};
pub use conformal::{in_conformal_set, split_conformal_threshold};
pub use dedup::{lsh_cluster, minhash, shingle};
pub use fdr::{benjamini_hochberg, e_bh, AlphaInvesting};
pub use fingerprint::{fastcdc, fingerprint, match_level, BaselineEntry};
