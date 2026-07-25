//! Stable integer identifiers used throughout the index.
//!
//! Everything that can be compared is compared as a `u32`. Interning turns
//! strings into [`Spur`]s; symbols, files and condensation nodes get their own
//! `u32` id spaces. Keeping these distinct types prevents the classic bug of
//! indexing the CSR with a file id.

use lasso::Spur;

/// Interned string key. Re-exported so the rest of the crate never names
/// `lasso` directly.
pub type SpurKey = Spur;

/// A source file. Indexes [`crate::source::SourceMap`].
pub type FileId = u32;
/// A declared symbol (fn, struct, …). Indexes [`crate::index::Index::symbols`].
pub type SymbolId = u32;
/// A node in the SCC condensation of the call graph. Indexes the condensation
/// CSR; one per strongly-connected component.
pub type NodeId = u32;

/// Sentinel for "no symbol" — distinct from a valid `SymbolId(0)`.
pub const NO_SYMBOL: SymbolId = SymbolId::MAX;
