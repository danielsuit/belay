//! Source file storage: per-file bytes + line tables.
//!
//! We hold each file as `Arc<[u8]>` (mmap-equivalent for our purposes — the
//! whole 50k-LOC gateway is a few MB; `read_span` is a slice, never a read).
//! A [`LineTable`] per file converts `proc-macro2` line/column to byte offsets.

use crate::ids::FileId;
use crate::span::{LineCol, LineTable, Span};
use std::path::{Path, PathBuf};
use std::sync::Arc;

#[derive(Clone, Debug)]
pub struct SourceFile {
    pub id: FileId,
    pub path: PathBuf,
    /// Canonicalized relative path (for stable cross-platform keys).
    pub rel_path: String,
    pub bytes: Arc<[u8]>,
    pub line_table: LineTable,
}

impl SourceFile {
    pub fn read_span(&self, start: u32, end: u32) -> &str {
        let end = end.min(self.bytes.len() as u32);
        if start >= end {
            return "";
        }
        // Source is valid UTF-8 (Rust source). A byte subrange of UTF-8 is
        // only valid if it lands on char boundaries; spans from proc-macro2 do.
        std::str::from_utf8(&self.bytes[start as usize..end as usize]).unwrap_or("")
    }

    /// Convert a `proc-macro2` `LineCol` (1-based line, **0-based** UTF-8
    /// character column) to a byte offset in `self.bytes`.
    ///
    /// proc-macro2's column is 0-indexed in *characters* (see proc-macro2
    /// `location.rs`), not bytes — so for multibyte lines we walk the line's
    /// chars rather than adding the column to the line start.
    fn byte_offset(&self, lc: LineCol) -> u32 {
        let starts = &self.line_table.line_starts;
        let line_idx = (lc.line as usize)
            .saturating_sub(1)
            .min(starts.len().saturating_sub(1));
        let line_start = starts[line_idx] as usize;
        let line_end = if line_idx + 1 < starts.len() {
            // Drop the trailing newline (and any '\r') so the line slice is just
            // the content; a column past the last char clamps to here.
            let mut end = starts[line_idx + 1] as usize;
            while end > line_start && matches!(self.bytes[end - 1], b'\n' | b'\r') {
                end -= 1;
            }
            end
        } else {
            self.bytes.len()
        };
        let line = std::str::from_utf8(&self.bytes[line_start..line_end]).unwrap_or("");
        // The column-th character's byte offset; if the column points at or past
        // the end of the line, clamp to line_end.
        match line.char_indices().nth(lc.column) {
            Some((i, _)) => (line_start + i) as u32,
            None => line_end as u32,
        }
    }

    /// Build a byte [`Span`] from proc-macro2 line/column endpoints.
    pub fn span_of(&self, file: FileId, start: LineCol, end: LineCol) -> Span {
        let s = self.byte_offset(start);
        let e = self.byte_offset(end).max(s);
        Span { file, start: s, end: e }
    }
}

#[derive(Clone, Debug, Default)]
pub struct SourceMap {
    pub files: Vec<SourceFile>,
    /// rel_path -> FileId for stable lookup.
    pub by_path: rustc_hash::FxHashMap<String, FileId>,
}

impl SourceMap {
    pub fn get(&self, id: FileId) -> &SourceFile {
        &self.files[id as usize]
    }

    /// Read a [`crate::span::Span`] to its source string. The grounding
    /// invariant: every finding's bytes come from here.
    pub fn read_span(&self, span: &crate::span::Span) -> &str {
        self.files[span.file as usize].read_span(span.start, span.end)
    }
}

/// Read a file from disk into a [`SourceFile`]. Returns `None` for non-UTF-8 or
/// unreadable files (skipped silently by the walker).
pub fn load_file(id: FileId, abs: &Path, rel: &str) -> Option<SourceFile> {
    let bytes: Arc<[u8]> = Arc::from(std::fs::read(abs).ok()?.into_boxed_slice());
    // Validate UTF-8 up front so later slicing never panics.
    if std::str::from_utf8(&bytes).is_err() {
        return None;
    }
    let line_table = LineTable::from_bytes(&bytes);
    Some(SourceFile {
        id,
        path: abs.to_path_buf(),
        rel_path: rel.to_string(),
        bytes,
        line_table,
    })
}
