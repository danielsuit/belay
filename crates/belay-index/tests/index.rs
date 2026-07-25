//! M0 + M1 verification gates (§VII).
//!
//! - span line-accuracy against a `rustfmt`-stable reparse
//! - cold index builds on a real-shaped fixture
//! - `reaches()` agrees with brute-force BFS on 1e5 random pairs
//! - condensation is a DAG
//! - bit-parallel BFS matches per-source BFS
//! - entry-point detection finds the axum handler and `main`

use belay_index::graph::CsrGraph;
use belay_index::reach::{bit_parallel_bfs, ReachLabels};
use belay_index::scc::condense;
use belay_index::{Index, LineCol, LineTable};
use std::path::PathBuf;

fn fixture_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixture")
}

#[test]
fn line_table_is_byte_accurate() {
    let src = "fn a() {\n    let x = 1; // c\n    b();\n}\n".as_bytes();
    let lt = LineTable::from_bytes(src);
    // proc-macro2 columns are 0-based: column 0 = first char of the line.
    assert_eq!(lt.to_byte(LineCol::new(1, 0)), Some(0));
    // "fn a() {" — '{' is at byte 7 (0-based column 7).
    assert_eq!(lt.to_byte(LineCol::new(1, 7)), Some(7));
    // Line 2 starts at byte 9 (after the "\n" at index 8).
    assert_eq!(lt.to_byte(LineCol::new(2, 0)), Some(9));
    // EOF clamp: line 99 returns None.
    assert_eq!(lt.to_byte(LineCol::new(99, 1)), None);
}

#[test]
fn index_builds_and_finds_entry_points() {
    let idx = Index::build(&fixture_root());
    // The fixture has a handful of symbols.
    assert!(idx.symbol_count() >= 8, "symbol_count={}", idx.symbol_count());
    assert!(!idx.entry_points().is_empty(), "no entry points detected");

    // `main` should be detected as an entry point.
    let mains: Vec<_> = idx
        .entry_points()
        .iter()
        .filter(|&&id| idx.name(id) == "main")
        .collect();
    assert!(!mains.is_empty(), "main not flagged as entry");

    // The axum handler `cache_get` should be detected via extractor param.
    let h = idx
        .entry_points()
        .iter()
        .find(|&&id| idx.name(id) == "cache_get");
    assert!(h.is_some(), "axum handler cache_get not detected");
}

#[test]
fn bit_parallel_small_dag() {
    // 0 -> 1 -> 2; 3 isolated.
    let g = CsrGraph::from_edges(4, vec![(0, 1), (1, 2)]);
    let reach = bit_parallel_bfs(&g, &[0, 1, 2, 3]);
    assert_eq!((reach[2] >> 0) & 1, 1, "0 should reach 2");
    assert_eq!((reach[0] >> 3) & 1, 0, "3 should not reach 0");
    assert_eq!((reach[1] >> 3) & 1, 0, "3 should not reach 1");
    assert_eq!((reach[2] >> 3) & 1, 0, "3 should not reach 2");
}

#[test]
fn read_span_returns_exact_source() {
    let idx = Index::build(&fixture_root());
    let id = idx.definition_of("cache_get").expect("cache_get defined");
    let sym = idx.symbol(id);
    let text = idx.read_span(&sym.name_span);
    assert_eq!(text, "cache_get");
}

#[test]
fn reaches_agrees_with_brute_force_bfs() {
    let idx = Index::build(&fixture_root());
    let g = &idx.graph;
    let n = g.node_count();
    if n < 2 {
        return;
    }

    // Deterministic PRNG (no Math.random in the harness; tests are fine to use
    // a seedable std rng).
    let mut rng = Lcg::new(0xdead_beef);
    let mut checked = 0u32;
    let mut mismatches = 0u32;
    while checked < 100_000 {
        let u = rng.next() % n;
        let v = rng.next() % n;
        let bfs = g.bfs_reachable(u, v);
        let label = idx.reaches(u, v);
        if bfs != label {
            mismatches += 1;
        }
        checked += 1;
    }
    assert_eq!(mismatches, 0, "reaches() disagrees with BFS on {checked} pairs");
}

#[test]
fn condensation_is_acyclic() {
    let idx = Index::build(&fixture_root());
    assert!(idx.condensation.is_acyclic(), "condensation has a self-loop");
}

#[test]
fn bit_parallel_bfs_matches_per_source() {
    let idx = Index::build(&fixture_root());
    let dag = &idx.condensation.dag;
    let n = dag.node_count();
    if n == 0 {
        return;
    }
    let sources: Vec<u32> = (0..n.min(64)).collect();
    let reach = bit_parallel_bfs(dag, &sources);
    for (i, &s) in sources.iter().enumerate() {
        let truth = dag.reachable_set(s);
        for w in 0..n {
            let expected = truth.contains(w as usize);
            let got = (reach[w as usize] >> i) & 1 == 1;
            assert_eq!(got, expected, "bit-parallel BFS mismatch src={s} node={w}");
        }
    }
}

#[test]
fn synthetic_graph_reach_and_scc() {
    // A -> B -> C, C -> A (cycle A,B,C), D -> B, E isolated.
    // 5 nodes; SCC {A,B,C}, {D}, {E}.
    let edges = vec![(0, 1), (1, 2), (2, 0), (3, 1)];
    let g = CsrGraph::from_edges(5, edges);
    let cond = condense(&g);
    // A,B,C in one SCC.
    assert_eq!(cond.scc_of(0), cond.scc_of(1));
    assert_eq!(cond.scc_of(1), cond.scc_of(2));
    // D and E each their own.
    assert_ne!(cond.scc_of(3), cond.scc_of(0));
    assert_ne!(cond.scc_of(4), cond.scc_of(0));
    assert!(cond.is_acyclic());
    // D reaches A (via B). E reaches nothing.
    let labels = ReachLabels::build(&cond.dag, 1024);
    let d_scc = cond.scc_of(3);
    let a_scc = cond.scc_of(0);
    let e_scc = cond.scc_of(4);
    assert!(labels.reaches(&cond.dag, d_scc, a_scc), "D should reach A");
    assert!(!labels.reaches(&cond.dag, e_scc, a_scc), "E should not reach A");
}

/// A tiny deterministic LCG so the property test is reproducible without
/// pulling in a rand dependency.
struct Lcg {
    state: u64,
}
impl Lcg {
    fn new(seed: u64) -> Self {
        Self { state: seed }
    }
    fn next(&mut self) -> u32 {
        // Numerical-constants LCG.
        self.state = self.state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        (self.state >> 32) as u32
    }
}
