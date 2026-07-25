//! Thread-safe string interning via `lasso`.
//!
//! Every module path, symbol name and type name becomes a `u32` [`Spur`][s].
//! Symbol comparison is then integer comparison, and `FxHashMap<Spur, _>`
//! lookups are nearly free. One `ThreadedRodeo` for the whole index; readers
//! never lock the table (it only grows).
//!
//! [s]: lasso::Spur

use lasso::ThreadedRodeo;
use std::sync::Arc;

#[derive(Clone, Debug)]
pub struct Interner {
    /// The writer; `get_or_intern` takes a per-key lock but is append-only.
    rodeo: Arc<ThreadedRodeo>,
}

impl Default for Interner {
    fn default() -> Self {
        Self::new()
    }
}

impl Interner {
    pub fn new() -> Self {
        Self {
            rodeo: Arc::new(ThreadedRodeo::new()),
        }
    }

    /// Intern a string, returning its stable key.
    pub fn get_or_intern(&self, s: &str) -> crate::ids::SpurKey {
        self.rodeo.get_or_intern(s)
    }

    /// Intern from a `proc-macro2` identifier (the common case).
    pub fn intern_ident(&self, ident: &proc_macro2::Ident) -> crate::ids::SpurKey {
        self.rodeo.get_or_intern(ident.to_string())
    }

    /// Resolve a key back to its string. O(1).
    pub fn resolve(&self, key: crate::ids::SpurKey) -> &str {
        self.rodeo.resolve(&key)
    }
}
