//! Spans as byte offsets, not strings.
//!
//! `proc-macro2` (with `span-locations`) reports `LineColumn { line, column }`
//! — **1-based line, 0-based UTF-8 character column** (see proc-macro2
//! `location.rs`). We convert to byte offsets against a per-file line-start
//! table so that `read_span` is a slice into the mmap'd source, never a parse
//! or an allocation. The character→byte walk for multibyte lines lives on
//! [`crate::source::SourceFile`]; the [`LineTable`] helpers here are the
//! ASCII-fast-path versions used in tests.

use crate::ids::FileId;

/// A byte-offset range within a single file. `end` is exclusive.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct Span {
    pub file: FileId,
    pub start: u32,
    pub end: u32,
}

impl Span {
    pub const fn new(file: FileId, start: u32, end: u32) -> Self {
        Self { file, start, end }
    }

    /// Empty span at `start` — used for synthetic / unresolved sites.
    pub const fn point(file: FileId, start: u32) -> Self {
        Self { file, start, end: start }
    }

    pub const fn len(&self) -> u32 {
        self.end.saturating_sub(self.start)
    }

    pub const fn is_empty(&self) -> bool {
        self.end <= self.start
    }

    /// Does `self` cover `other` (same file, byte range contains it)?
    pub fn contains(&self, other: &Span) -> bool {
        self.file == other.file && self.start <= other.start && other.end <= self.end
    }
}

/// 1-based `proc-macro2` line/column, convertible to a [`Span`] byte range.
#[derive(Clone, Copy, Debug, Default)]
pub struct LineCol {
    pub line: usize,
    pub column: usize,
}

impl LineCol {
    pub const fn new(line: usize, column: usize) -> Self {
        Self { line, column }
    }
}

/// Per-file byte-offset table: `line_starts[i]` is the byte offset of the start
/// of 1-based line `i+1`. `line_starts[0]` is always `0`.
///
/// Build once per file; `to_byte` is then an O(1) array index. A slice into the
/// mmap'd source is the whole point of storing byte offsets.
#[derive(Clone, Debug, Default)]
pub struct LineTable {
    /// Byte offset of the start of each line. Length = line count + 1, where
    /// the final entry is the total byte length (acts as a sentinel end).
    pub line_starts: Vec<u32>,
}

impl LineTable {
    /// Build a line-start table by a single scan of the source bytes.
    pub fn from_bytes(src: &[u8]) -> Self {
        let nl_count = src.iter().filter(|&&b| b == b'\n').count();
        let mut starts = Vec::with_capacity(nl_count + 2);
        starts.push(0);
        for (i, &b) in src.iter().enumerate() {
            if b == b'\n' {
                starts.push((i + 1) as u32);
            }
        }
        starts.push(src.len() as u32);
        Self { line_starts: starts }
    }

    /// Convert a `LineCol` (1-based line, 0-based column) to a byte offset.
    /// Returns `None` for a line past EOF. ASCII fast path — for multibyte
    /// lines use [`crate::source::SourceFile::span_of`].
    pub fn to_byte(&self, lc: LineCol) -> Option<u32> {
        let line_idx = lc.line.checked_sub(1)?;
        let start = *self.line_starts.get(line_idx)?;
        // Columns are 0-based within the line.
        let line_end = self
            .line_starts
            .get(line_idx + 1)
            .copied()
            .unwrap_or(start);
        let off = (start as usize) + lc.column;
        // Clamp to the line's end — proc-macro2 columns occasionally point one
        // past the final char on the last line.
        let clamped = off.min(line_end as usize);
        Some(clamped as u32)
    }

    /// Convert a `(start, end)` `LineCol` pair to a byte [`Span`].
    pub fn to_span(&self, file: FileId, start: LineCol, end: LineCol) -> Span {
        let s = self.to_byte(start).unwrap_or(0);
        let e = self.to_byte(end).unwrap_or(s).max(s);
        Span::new(file, s, e)
    }
}
