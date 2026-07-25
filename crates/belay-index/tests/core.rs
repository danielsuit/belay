//! M0/M1 verification gates (§VII):
//!   - spans line-accurate against known source
//!   - reaches() agrees with brute-force BFS on 1e5 random pairs
//!   - condensation is a true DAG
//!   - bit-parallel BFS agrees with per-source BFS
//!   - axum handler detected as an entry point; a plain helper is not

use belay_index::{bit_parallel_bfs, condense, CsrGraph, Index, ReachLabels, SymbolKind};
use std::fs;
use tempfile::tempdir;

// ---- Deterministic LCG (tests must be reproducible; Math.random is not God's
// domain here, it's just banned in workflow scripts). ----
struct Rng(u64);
impl Rng {
    fn new(seed: u64) -> Self {
        Self(seed)
    }
    fn next(&mut self) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        self.0
    }
    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
}

fn build_random_graph(n: u32, edge_denom: u64, seed: u64, add_cycles: bool) -> CsrGraph {
    let mut rng = Rng::new(seed);
    let mut edges: Vec<(u32, u32)> = Vec::new();
    for i in 0..n {
        for j in 0..n {
            if i == j {
                continue;
            }
            if rng.next() % edge_denom == 0 {
                edges.push((i, j));
            }
        }
    }
    if add_cycles {
        // Add a few mutual-recursion clusters to exercise SCC condensation.
        for _ in 0..(n / 20).max(1) {
            let a = rng.below(n as u64) as u32;
            let b = rng.below(n as u64) as u32;
            if a != b {
                edges.push((a, b));
                edges.push((b, a));
            }
        }
    }
    CsrGraph::from_edges(n, edges)
}

#[test]
fn reaches_matches_brute_force_bfs() {
    let n = 300;
    let g = build_random_graph(n, 25, 0xC0FFEE, true);
    let cond = condense(&g);
    assert!(cond.is_acyclic(), "condensation must be a DAG");
    let labels = ReachLabels::build(&cond.dag, 1024);

    let mut rng = Rng::new(0x1234567);
    let mut checked = 0;
    let mut mismatches = 0;
    while checked < 100_000 {
        let u = rng.below(n as u64) as u32;
        let v = rng.below(n as u64) as u32;
        let su = cond.scc_of(u);
        let sv = cond.scc_of(v);
        let by_labels = labels.reaches(&cond.dag, su, sv);
        let by_bfs = cond.dag.bfs_reachable(su, sv);
        if by_labels != by_bfs {
            mismatches += 1;
        }
        checked += 1;
    }
    assert_eq!(mismatches, 0, "labels disagree with BFS on {mismatches}/{checked} pairs");
}

#[test]
fn bit_parallel_matches_single_source() {
    let n = 200;
    let g = build_random_graph(n, 20, 0xBEEF, false);
    let sources: Vec<u32> = (0..n).collect();
    let reach = bit_parallel_bfs(&g, &sources);
    assert_eq!(reach.len(), n as usize);
    // bit_parallel packs 64 sources per chunk; the bit index is local to its
    // chunk, so iterate chunk-by-chunk when comparing against single-source BFS.
    for (chunk_idx, chunk) in sources.chunks(64).enumerate() {
        for (local_i, &s) in chunk.iter().enumerate() {
            let single = g.reachable_set(s);
            for w in 0..n {
                let bp = (reach[w as usize] >> local_i) & 1 == 1;
                let ss = single.contains(w as usize);
                assert_eq!(
                    bp, ss,
                    "bit-parallel disagrees at chunk={chunk_idx} local_i={local_i} (source={s}) target={w}"
                );
            }
        }
    }
}

#[test]
fn scc_condensation_is_acyclic_and_complete() {
    // Two cycles + a bridge: 0<->1<->2 (one SCC), 3<->4 (one SCC), edge 2->3.
    let g = CsrGraph::from_edges(
        6,
        vec![(0, 1), (1, 2), (2, 0), (3, 4), (4, 3), (2, 3), (5, 0)],
    );
    let cond = condense(&g);
    assert!(cond.is_acyclic());
    // 3 SCCs: {0,1,2}, {3,4}, {5}.
    assert_eq!(cond.scc_count, 3);
    assert_eq!(cond.scc_of(0), cond.scc_of(1));
    assert_eq!(cond.scc_of(1), cond.scc_of(2));
    assert_eq!(cond.scc_of(3), cond.scc_of(4));
    assert_ne!(cond.scc_of(0), cond.scc_of(3));
    assert_ne!(cond.scc_of(0), cond.scc_of(5));
}

fn write_workspace(code: &str) -> tempfile::TempDir {
    let dir = tempdir().unwrap();
    let path = dir.path().join("src/lib.rs");
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(&path, code).unwrap();
    dir
}

#[test]
fn span_accuracy_against_known_source() {
    let code = "fn handle(req: u64) -> u64 {\n    let x = req;\n    x.unwrap_me()\n}\n";
    let dir = write_workspace(code);
    let idx = Index::build(dir.path());
    let sym = idx
        .symbols
        .iter()
        .find(|s| s.kind == SymbolKind::Fn)
        .unwrap();
    // Full def span reconstructs the whole fn.
    assert_eq!(
        idx.read_span(&sym.span),
        "fn handle(req: u64) -> u64 {\n    let x = req;\n    x.unwrap_me()\n}"
    );
    // Name span is exactly the identifier.
    assert_eq!(idx.read_span(&sym.name_span), "handle");
}

#[test]
fn axum_handler_detected_as_entry_point() {
    let code = "use axum::extract::State;\n\
                fn handler(State(s): State<AppState>, req: u64) -> u64 { req }\n\
                fn helper(x: u64) -> u64 { x + 1 }\n";
    let dir = write_workspace(code);
    let idx = Index::build(dir.path());
    let entries: Vec<&str> = idx.entry_points().iter().map(|&id| idx.qual(id)).collect();
    assert!(
        entries.iter().any(|q| q.contains("handler")),
        "handler should be an entry point: {entries:?}"
    );
    assert!(
        !entries.iter().any(|q| q.contains("helper")),
        "helper should NOT be an entry point: {entries:?}"
    );
}
