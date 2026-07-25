//! The RustSec corpus: 40–60 advisories mapped onto the taxonomy, vulnerable
//! and patched tags both checked out (§M3). FP rate is measured on the
//! patched tag — same class + same file = a confirmed FP, no hand labeling.

use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CorpusEntry {
    pub id: String,
    pub class: String,
    pub vuln_file: String,
    pub vuln_line: u32,
    pub patch_file: String,
    pub patch_line: u32,
    /// Lines of code of the scanned crate (for tokens/KLOC normalization).
    pub kloc: f64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Corpus {
    pub entries: Vec<CorpusEntry>,
}

impl Corpus {
    pub fn from_json(s: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(s)
    }
    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(self).unwrap()
    }
    pub fn kloc(&self) -> f64 {
        self.entries.iter().map(|e| e.kloc).sum()
    }
    pub fn len(&self) -> usize {
        self.entries.len()
    }
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}
