//! The [`Index`]: everything the model is ever asked about.
//!
//! Build pipeline (§II.1 → §II.6): parse → symbols → CSR call graph → Tarjan
//! condensation → 2-hop labels. Query API mirrors the four semantic tools in
//! §I.5 — `read_span`, `definition_of`, `callers_of`, `reaches` — plus entry
//! points and graph dumps.

use crate::graph::CsrGraph;
use crate::ids::{FileId, SpurKey, SymbolId};
use crate::interner::Interner;
use crate::parse;
use crate::reach::ReachLabels;
use crate::scc::{condense, Condensation};
use crate::source::{SourceFile, SourceMap};
use crate::span::Span;
use crate::symbol::Symbol;
use std::path::{Path, PathBuf};

/// The frozen, queryable view of a workspace.
pub struct Index {
    pub interner: Interner,
    pub root: PathBuf,
    pub sources: SourceMap,
    pub symbols: Vec<Symbol>,
    /// Call graph over [`SymbolId`].
    pub graph: CsrGraph,
    /// SCC condensation of `graph`.
    pub condensation: Condensation,
    /// 2-hop labels over the condensation DAG.
    pub reach: ReachLabels,
    /// Detected entry-point symbols.
    pub entry_points: Vec<SymbolId>,
    /// `by_qual[qual]` → symbol; the `definition_of` fast path.
    by_qual: rustc_hash::FxHashMap<SpurKey, SymbolId>,
    /// `by_name[name]` → symbols; disambiguation fallback.
    by_name: rustc_hash::FxHashMap<SpurKey, Vec<SymbolId>>,
}

impl Index {
    /// Cold build: parse + graph + condensation + labels.
    pub fn build(root: &Path) -> Self {
        let interner = Interner::new();
        let merged = parse::parse_workspace(root, &interner);
        Self::from_merged(root.to_path_buf(), interner, merged)
    }

    pub(crate) fn from_merged(
        root: PathBuf,
        interner: Interner,
        merged: parse::Merged,
    ) -> Self {
        let n = merged.symbols.len() as u32;
        let graph = CsrGraph::from_edges(n, merged.edges.clone());
        let condensation = condense(&graph);
        // 2-hop labels over the condensation DAG. Cap is generous; incomplete
        // nodes fall back to BFS so correctness never depends on the cap.
        let reach = ReachLabels::build(&condensation.dag, 1024);

        let mut by_qual: rustc_hash::FxHashMap<SpurKey, SymbolId> =
            rustc_hash::FxHashMap::default();
        let mut by_name: rustc_hash::FxHashMap<SpurKey, Vec<SymbolId>> =
            rustc_hash::FxHashMap::default();
        let mut entry_points = Vec::new();
        for s in &merged.symbols {
            by_qual.insert(s.qual, s.id);
            by_name.entry(s.name).or_default().push(s.id);
            if s.entry {
                entry_points.push(s.id);
            }
        }

        let sources = SourceMap {
            files: merged.sources,
            by_path: rustc_hash::FxHashMap::default(),
        };

        Self {
            interner,
            root,
            sources,
            symbols: merged.symbols,
            graph,
            condensation,
            reach,
            entry_points,
            by_qual,
            by_name,
        }
    }

    pub fn symbol_count(&self) -> usize {
        self.symbols.len()
    }

    pub fn file_count(&self) -> usize {
        self.sources.files.len()
    }

    /// `read_span(path, start, end)` — a slice into the mmap'd source, never a
    /// read or allocation.
    pub fn read_span(&self, span: &Span) -> &str {
        self.sources.read_span(span)
    }

    pub fn source(&self, file: FileId) -> &SourceFile {
        self.sources.get(file)
    }

    /// `definition_of(symbol)` — qualified path first, then unique short name.
    pub fn definition_of(&self, sym: &str) -> Option<SymbolId> {
        let q = self.interner.get_or_intern(sym);
        if let Some(&id) = self.by_qual.get(&q) {
            return Some(id);
        }
        let last = sym.rsplit("::").next().unwrap_or(sym);
        let l = self.interner.get_or_intern(last);
        let cands = self.by_name.get(&l)?;
        match cands.as_slice() {
            [] => None,
            [only] => Some(*only),
            many => {
                // Prefer a fn/variant if multiple share the name.
                many.iter()
                    .find(|&&id| self.symbols[id as usize].kind.is_callable())
                    .copied()
            }
        }
    }

    /// `callers_of(symbol)` — reverse-CSR scan, O(in-deg).
    pub fn callers_of(&self, sym: SymbolId) -> &[SymbolId] {
        // `SymbolId` is `u32`; the CSR stores `u32`. Same memory.
        let raw: &[u32] = self.graph.rev(sym);
        unsafe { std::slice::from_raw_parts(raw.as_ptr() as *const SymbolId, raw.len()) }
    }

    pub fn callees_of(&self, sym: SymbolId) -> &[SymbolId] {
        let raw: &[u32] = self.graph.out(sym);
        unsafe { std::slice::from_raw_parts(raw.as_ptr() as *const SymbolId, raw.len()) }
    }

    /// `reaches(from, to)` — 2-hop label intersection on the condensation, with
    /// BFS fallback. Symbols in the same SCC are mutually reachable.
    pub fn reaches(&self, from: SymbolId, to: SymbolId) -> bool {
        if from == to {
            return true;
        }
        let sf = self.condensation.scc_of(from);
        let st = self.condensation.scc_of(to);
        if sf == st {
            return true;
        }
        self.reach.reaches(&self.condensation.dag, sf, st)
    }

    /// A witness path of symbol ids from `from` to `to`, if reachable.
    /// BFS over the condensation, then expanded through SCC members to find a
    /// concrete call chain. Best-effort — not guaranteed shortest.
    pub fn witness(&self, from: SymbolId, to: SymbolId) -> Option<Vec<SymbolId>> {
        if from == to {
            return Some(vec![from]);
        }
        // BFS over condensation for a node path, then pick a representative
        // member per SCC that has a real edge to the next.
        let sf = self.condensation.scc_of(from);
        let st = self.condensation.scc_of(to);
        if sf == st {
            return Some(vec![from, to]);
        }
        let node_path = bfs_node_path(&self.condensation.dag, sf, st)?;
        let mut chain = vec![from];
        for window in node_path.windows(2) {
            let (a_scc, b_scc) = (window[0], window[1]);
            // Find a symbol in `a_scc`'s member set with an edge into `b_scc`.
            let members_a = &self.condensation.members[a_scc as usize];
            let members_b = &self.condensation.members[b_scc as usize];
            let in_b: rustc_hash::FxHashSet<u32> =
                members_b.iter().copied().collect();
            let mut found = None;
            for &m in members_a {
                for &tgt in self.graph.out(m) {
                    if in_b.contains(&tgt) {
                        found = Some((m, tgt));
                        break;
                    }
                }
                if found.is_some() {
                    break;
                }
            }
            let (m, tgt) = found?;
            if chain.last() != Some(&m) {
                chain.push(m);
            }
            chain.push(tgt);
        }
        Some(chain)
    }

    pub fn entry_points(&self) -> &[SymbolId] {
        &self.entry_points
    }

    pub fn symbol(&self, id: SymbolId) -> &Symbol {
        &self.symbols[id as usize]
    }

    pub fn name(&self, id: SymbolId) -> &str {
        self.interner.resolve(self.symbols[id as usize].name)
    }

    pub fn qual(&self, id: SymbolId) -> &str {
        self.interner.resolve(self.symbols[id as usize].qual)
    }
}

/// BFS for a node path in a DAG (used to build a witness).
fn bfs_node_path(dag: &CsrGraph, from: u32, to: u32) -> Option<Vec<u32>> {
    let n = dag.node_count() as usize;
    let mut parent = vec![u32::MAX; n];
    let mut visited = fixedbitset::FixedBitSet::with_capacity(n);
    let mut q = std::collections::VecDeque::new();
    visited.insert(from as usize);
    q.push_back(from);
    while let Some(u) = q.pop_front() {
        if u == to {
            // Reconstruct.
            let mut path = vec![to];
            let mut cur = to;
            while cur != from {
                cur = parent[cur as usize];
                if cur == u32::MAX {
                    return None;
                }
                path.push(cur);
            }
            path.reverse();
            return Some(path);
        }
        for &v in dag.out(u) {
            if !visited.put(v as usize) {
                parent[v as usize] = u;
                q.push_back(v);
            }
        }
    }
    None
}
