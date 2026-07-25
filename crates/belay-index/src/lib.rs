//! belay-index: parse, symbols, spans, CSR graph, SCC, 2-hop reachability.
//!
//! M0 (parse / symbols / spans) and M1 (graph / SCC / labels / entry points)
//! live here. Everything the model is asked is a question about the [`Index`];
//! index quality caps scan quality.

pub mod cache;
pub mod entry;
pub mod graph;
pub mod ids;
pub mod index;
pub mod interner;
pub mod parse;
pub mod reach;
pub mod scc;
pub mod source;
pub mod span;
pub mod symbol;

pub use graph::CsrGraph;
pub use ids::{FileId, NodeId, SpurKey, SymbolId, NO_SYMBOL};
pub use index::Index;
pub use interner::Interner;
pub use reach::{bit_parallel_bfs, ReachLabels};
pub use scc::{condense, tarjan_scc, Condensation};
pub use source::{SourceFile, SourceMap};
pub use span::{LineCol, LineTable, Span};
pub use symbol::{Symbol, SymbolKind};
