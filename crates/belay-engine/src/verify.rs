//! Span verification — the grounding rule (§I.1, §M4).
//!
//! Every finding carries verified file bytes or it is discarded. A candidate
//! that cites a span must actually cite bytes present in the file; on mismatch
//! it is dropped before it can cost another token downstream. This is the
//! single biggest defense against hallucinated findings.

use belay_index::{FileId, Index, Span};

/// A raw candidate finding as emitted by pass 1, before verification.
#[derive(Clone, Debug)]
pub struct RawFinding {
    pub class: String,
    pub rubric_version: String,
    pub file: FileId,
    pub span: Span,
    /// The source bytes the model claims are at `span`.
    pub cited_snippet: String,
    pub confidence: f64,
    pub rationale: String,
}

/// Verify that `span` in `index` actually contains `cited_snippet`. On a
/// mismatch (the model invented bytes, or the file shifted) the finding is
/// discarded.
pub fn verify_span(index: &Index, span: &Span, cited_snippet: &str) -> bool {
    if span.end < span.start {
        return false;
    }
    let actual = index.read_span(span);
    // Normalize trailing whitespace for robustness; the bytes must otherwise match.
    actual.trim_end() == cited_snippet.trim_end()
}

/// Verify a finding's cited span against the index. Returns the finding back
/// if it verifies, or `None` to discard.
pub fn verify_finding(index: &Index, f: &RawFinding) -> Option<RawFinding> {
    if verify_span(index, &f.span, &f.cited_snippet) {
        Some(f.clone())
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    fn index_with_file() -> (tempfile::TempDir, Index, FileId, Span) {
        let dir = tempdir().unwrap();
        let path = dir.path().join("src/lib.rs");
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        let code = "fn handle_request(req: u64) -> u64 { req + 1 }\n";
        fs::write(&path, code).unwrap();
        let idx = Index::build(dir.path());
        // Find the fn symbol.
        let sym = idx
            .symbols
            .iter()
            .find(|s| s.kind == belay_index::SymbolKind::Fn)
            .unwrap();
        let (file, span) = (sym.file, sym.span.clone());
        (dir, idx, file, span)
    }

    #[test]
    fn matching_snippet_verifies() {
        let (_dir, idx, _file, span) = index_with_file();
        let actual = idx.read_span(&span).to_string();
        assert!(verify_span(&idx, &span, &actual));
    }

    #[test]
    fn mismatched_snippet_discarded() {
        let (_dir, idx, _file, span) = index_with_file();
        assert!(!verify_span(&idx, &span, "fn totally_made_up() {}"));
    }
}
