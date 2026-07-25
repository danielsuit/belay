//! belay-eval: corpus, metrics, and statistical comparison of prompt variants
//! (§M3, §VI.5).
//!
//! The rule that makes the tool worth building: **never accept a prompt
//! change whose bootstrap CI on Δdetection includes zero.** Without it you are
//! tuning against noise, and prompt tuning against noise is how scanners rot.

pub mod bootstrap;
pub mod corpus;
pub mod hyperband;
pub mod metrics;

pub use bootstrap::{mcnemar, paired_bootstrap_ci};
pub use corpus::{Corpus, CorpusEntry};
pub use hyperband::successive_halving;
pub use metrics::{compute, Metrics, Prediction};
