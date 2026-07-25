//! Symbols: declared items extracted from the AST.
//!
//! A symbol is anything with a name and a definition site we can point at.
//! The qualified path (`qual`) is interned so a finding can name `"crate::mod::f"`
//! without holding a string. `name_span` is the identifier alone — used for
//! stable fingerprints that survive edits to the body.

use crate::ids::{FileId, SpurKey, SymbolId};
use crate::span::Span;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum SymbolKind {
    Fn,
    Struct,
    Enum,
    Variant,
    Trait,
    /// `impl Trait for Type` blocks — named by their self-type.
    Impl,
    Mod,
    Const,
    Static,
    TypeAlias,
    Macro,
    Field,
}

impl SymbolKind {
    pub fn is_callable(&self) -> bool {
        matches!(self, SymbolKind::Fn | SymbolKind::Variant)
    }
}

#[derive(Clone, Debug)]
pub struct Symbol {
    pub id: SymbolId,
    /// Short identifier (`f`).
    pub name: SpurKey,
    /// Qualified path (`crate::mod::f`). Best-effort from `syn`.
    pub qual: SpurKey,
    pub kind: SymbolKind,
    pub file: FileId,
    /// Full definition span (whole item).
    pub span: Span,
    /// Identifier span alone.
    pub name_span: Span,
    /// Whether this symbol is a detected entry point (axum handler, main, …).
    pub entry: bool,
    /// Human-readable reason it was flagged as an entry point, if any.
    pub entry_reason: Option<String>,
}

impl Symbol {
    pub fn is_entry(&self) -> bool {
        self.entry
    }
}
