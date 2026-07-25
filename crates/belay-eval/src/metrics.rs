//! Scan metrics (§M3): detection, localization, FP rate (on the patched tag),
//! discard rate, tokens/KLOC, cache hit rate.

use crate::corpus::Corpus;

/// One prediction per (advisory, tag) run. `on_patched` distinguishes the
/// vulnerable-tag run (measures detection/localization) from the patched-tag
/// run (measures FP rate).
#[derive(Clone, Debug)]
pub struct Prediction {
    pub advisory: String,
    pub on_patched: bool,
    pub detected: bool,
    pub localized: bool,
    pub class: String,
    pub file: String,
    pub tokens: u64,
    pub discarded: bool,
    pub cache_hit: f64,
}

#[derive(Clone, Debug, Default)]
pub struct Metrics {
    /// Fraction of advisories detected on the vulnerable tag.
    pub detection: f64,
    /// Fraction of advisories with a finding localized to the patch hunk.
    pub localization: f64,
    /// On the patched tag: fraction of predictions that match the class AND
    /// file of a (now-patched) advisory — confirmed false positives.
    pub fp_rate: f64,
    pub discard_rate: f64,
    pub tokens_per_kloc: f64,
    pub cache_hit_rate: f64,
}

pub fn compute(preds: &[Prediction], corpus: &Corpus) -> Metrics {
    let n_adv = corpus.len().max(1) as f64;
    let mut detected = 0usize;
    let mut localized = 0usize;
    let mut fp = 0usize;
    let mut patched_preds = 0usize;
    let mut discarded = 0usize;
    let mut tokens = 0u64;
    let mut cache = 0.0;

    for p in preds {
        tokens += p.tokens;
        cache += p.cache_hit;
        if p.discarded {
            discarded += 1;
        }
        if !p.on_patched {
            if p.detected {
                detected += 1;
            }
            if p.localized {
                localized += 1;
            }
        } else {
            patched_preds += 1;
            // FP if class + file match a corpus advisory's patched location.
            if corpus.entries.iter().any(|e| e.class == p.class && e.patch_file == p.file) {
                fp += 1;
            }
        }
    }

    let total = preds.len().max(1) as f64;
    Metrics {
        detection: detected as f64 / n_adv,
        localization: localized as f64 / n_adv,
        fp_rate: if patched_preds > 0 {
            fp as f64 / patched_preds as f64
        } else {
            0.0
        },
        discard_rate: discarded as f64 / total,
        tokens_per_kloc: {
            let kloc = corpus.kloc().max(1.0);
            tokens as f64 / kloc
        },
        cache_hit_rate: if preds.is_empty() { 0.0 } else { cache / total },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::corpus::{Corpus, CorpusEntry};

    fn corpus() -> Corpus {
        Corpus {
            entries: vec![
                CorpusEntry { id: "a".into(), class: "panic-on-input".into(), vuln_file: "f.rs".into(), vuln_line: 1, patch_file: "f.rs".into(), patch_line: 1, kloc: 10.0 },
                CorpusEntry { id: "b".into(), class: "authz-missing".into(), vuln_file: "g.rs".into(), vuln_line: 5, patch_file: "g.rs".into(), patch_line: 5, kloc: 10.0 },
            ],
        }
    }

    #[test]
    fn detection_and_fp_computed() {
        let c = corpus();
        let preds = vec![
            Prediction { advisory: "a".into(), on_patched: false, detected: true, localized: true, class: "panic-on-input".into(), file: "f.rs".into(), tokens: 1000, discarded: false, cache_hit: 0.9 },
            Prediction { advisory: "b".into(), on_patched: false, detected: false, localized: false, class: "authz-missing".into(), file: "x.rs".into(), tokens: 500, discarded: false, cache_hit: 0.8 },
            // Patched-tag runs: one FP (same class+file as advisory a).
            Prediction { advisory: "a".into(), on_patched: true, detected: true, localized: false, class: "panic-on-input".into(), file: "f.rs".into(), tokens: 800, discarded: false, cache_hit: 0.9 },
            Prediction { advisory: "a".into(), on_patched: true, detected: false, localized: false, class: "injection".into(), file: "z.rs".into(), tokens: 200, discarded: true, cache_hit: 0.5 },
        ];
        let m = compute(&preds, &c);
        assert!((m.detection - 0.5).abs() < 1e-9);
        assert!((m.localization - 0.5).abs() < 1e-9);
        // 1 FP out of 2 patched-tag preds.
        assert!((m.fp_rate - 0.5).abs() < 1e-9);
        assert!((m.discard_rate - 0.25).abs() < 1e-9);
        // tokens/KLOC: 2500 tokens / 20 KLOC = 125.
        assert!((m.tokens_per_kloc - 125.0).abs() < 1e-6);
    }
}
