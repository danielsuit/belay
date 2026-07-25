//! A confirmed finding — the report-layer type.
//!
//! Pass 1 emits [`crate::verify::RawFinding`]; verification, FDR gating, and
//! near-duplicate collapse promote it to this [`Finding`], which the report
//! layer renders to SARIF / markdown / terminal.

use serde::Serialize;

#[derive(Clone, Copy, Debug, Serialize, PartialEq, Eq)]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

impl Severity {
    pub fn as_str(&self) -> &'static str {
        match self {
            Severity::Critical => "critical",
            Severity::High => "high",
            Severity::Medium => "medium",
            Severity::Low => "low",
            Severity::Info => "info",
        }
    }

    /// SARIF level.
    pub fn sarif_level(&self) -> &'static str {
        match self {
            Severity::Critical | Severity::High => "error",
            Severity::Medium => "warning",
            Severity::Low | Severity::Info => "note",
        }
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct Finding {
    pub id: u64,
    pub class: String,
    pub rubric_version: String,
    pub severity: Severity,
    /// Workspace-relative file path.
    pub file: String,
    /// Byte offsets (start, end).
    pub span: (u32, u32),
    /// 1-based line of the start.
    pub line: u32,
    pub message: String,
    /// The verified source bytes at the span.
    pub evidence: String,
    pub rationale: String,
    /// Calibrated P(vuln | evidence).
    pub confidence: f64,
    /// e-value from the §IV.2 accumulator.
    pub e_value: f64,
    /// p-value for FDR procedures.
    pub p_value: f64,
    pub fingerprint: [u8; 16],
    /// Near-duplicate cluster size (§IV.8).
    pub sites: u32,
}

impl Finding {
    pub fn primary_location(&self) -> (String, u32, u32) {
        (self.file.clone(), self.line, self.span.0)
    }
}
