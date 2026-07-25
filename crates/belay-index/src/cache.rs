//! Persistent index cache (redb) — §II.1 warm path.
//!
//! The warm path: mmap the cache, validate every file against mtime + blake3,
//! and if all match, skip the parse and rebuild the [`Index`] from the stored
//! symbol table + edges + SCC map.
//!
//! Status: the cold path is correct and tested (see `tests/`). The warm path
//! needs the cached symbols to carry their *strings*, not just `SpurKey`s
//! (a `Spur` only resolves against the interner that minted it, which doesn't
//! survive across processes). That schema change + redb wiring is the obvious
//! follow-up; for now [`build_cached`] falls through to a cold build so the
//! rest of the system has a stable `Index` to build on.

use crate::index::Index;
use std::path::Path;

/// Build an [`Index`], using the cache at `cache_path` if still valid.
///
/// Returns the index and whether the cache hit. Cache hits are not yet
/// implemented (see module docs); this always cold-builds and reports `false`.
pub fn build_cached(root: &Path, _cache_path: &Path) -> (Index, bool) {
    (Index::build(root), false)
}
