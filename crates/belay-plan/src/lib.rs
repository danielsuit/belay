//! belay-plan: the scheduling & cache-optimization layer (§III).
//!
//! Where the token bill is decided. The model is fixed; what varies by 5–20×
//! is what you send and in what order. This crate holds the prompt trie and
//! its DFS-optimal scan order (§III.2), the Belady hint stream (§III.3),
//! balanced connected tree partitioning + LPT (§III.4), and the CELF
//! budgeted-submodular-coverage solver (§III.5).

pub mod belady;
pub mod budget;
pub mod partition;
pub mod trie;

pub use belady::belady_hints;
pub use budget::{budgeted_coverage, Item};
pub use partition::{lpt, sharing_coefficient};
pub use trie::{Chain, PromptTrie};
