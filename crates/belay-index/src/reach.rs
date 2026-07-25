//! 2-hop reachability labels (Cohen et al.) built by pruned landmark labeling
//! (Akiba et al.), plus a bit-parallel BFS for the bulk "reachable from all
//! entry points" case.
//!
//! `reaches(u,v) ⟺ L_out(u) ∩ L_in(v) ≠ ∅`. A query is a sorted-set
//! intersection — a handful of `u32` comparisons. This is called every pass-2
//! turn and every planner relevance test; naive BFS per query is O(V+E) and
//! turns planning into the slow part of an LLM-bound program.
//!
//! Correctness contract: a query between two *complete* nodes is answered
//! exactly by the label intersection (the witness landmark ℓ lives in both
//! `L_out(u)` and `L_in(v)`, which depends only on *those two* nodes' labels).
//! If either endpoint was truncated by the label-size cap, we fall back to
//! BFS — so `reaches` always agrees with brute force, at the cost of speed,
//! never accuracy.

use crate::graph::CsrGraph;
use fixedbitset::FixedBitSet;

/// 2-hop labels over a condensation DAG (or any DAG).
#[derive(Clone, Debug)]
pub struct ReachLabels {
    /// `l_out[v]` = sorted landmarks reachable from `v`.
    pub l_out: Vec<Vec<u32>>,
    /// `l_in[v]` = sorted landmarks that can reach `v`.
    pub l_in: Vec<Vec<u32>>,
    /// Which nodes have complete (untruncated) labels. Incomplete ⟹ BFS
    /// fallback for any query touching them.
    pub complete: FixedBitSet,
    n: u32,
}

impl ReachLabels {
    /// Build labels over `dag`. `cap` bounds per-node label size; nodes that
    /// hit the cap are marked incomplete and fall back to BFS. Use
    /// `u32::MAX` for no cap (exact everywhere, possibly large labels).
    pub fn build(dag: &CsrGraph, cap: u32) -> Self {
        let n = dag.node_count();
        let mut l_out: Vec<Vec<u32>> = (0..n).map(|v| vec![v]).collect();
        let mut l_in: Vec<Vec<u32>> = (0..n).map(|v| vec![v]).collect();
        let mut complete = FixedBitSet::with_capacity(n as usize);
        complete.set_range(.., true);

        // Landmark order: degree descending (PLL heuristic for small labels).
        let mut order: Vec<u32> = (0..n).collect();
        order.sort_unstable_by_key(|&v| std::cmp::Reverse((dag.out_deg(v) as i64, v)));

        for &v in &order {
            // Forward pass: add v to L_in(w) for every w reachable from v
            // (out-edges), pruning nodes already covered w.r.t. v.
            pruned_traverse(
                dag,
                v,
                /*forward*/ true,
                &mut l_in,
                &l_out,
                cap,
                &mut complete,
            );
            // Backward pass: add v to L_out(w) for every w that can reach v
            // (rev-edges), pruning nodes already covered.
            pruned_traverse(
                dag,
                v,
                /*forward*/ false,
                &mut l_out,
                &l_in,
                cap,
                &mut complete,
            );
        }

        ReachLabels { l_out, l_in, complete, n }
    }

    /// The reachability query — O(|L_out(u)| + |L_in(v)|) sorted intersection.
    /// Falls back to BFS if either endpoint is incomplete.
    pub fn reaches(&self, dag: &CsrGraph, u: u32, v: u32) -> bool {
        if u == v {
            return true;
        }
        if (u as usize) < self.n as usize
            && (v as usize) < self.n as usize
            && self.complete.contains(u as usize)
            && self.complete.contains(v as usize)
        {
            // Sorted-set intersection.
            let a = &self.l_out[u as usize];
            let b = &self.l_in[v as usize];
            let (mut i, mut j) = (0, 0);
            while i < a.len() && j < b.len() {
                match a[i].cmp(&b[j]) {
                    std::cmp::Ordering::Less => i += 1,
                    std::cmp::Ordering::Greater => j += 1,
                    std::cmp::Ordering::Equal => return true,
                }
            }
            false
        } else {
            dag.bfs_reachable(u, v)
        }
    }

    pub fn node_count(&self) -> u32 {
        self.n
    }
}

/// Pruned traversal from landmark `v`.
///
/// `forward=true` follows out-edges and writes into `target` (= `l_in`),
/// checking coverage against `other` (= `l_out`). `forward=false` follows
/// rev-edges and writes into `l_out`, checking `l_in`. Symmetric, so one
/// function with a direction flag.
fn pruned_traverse(
    dag: &CsrGraph,
    v: u32,
    forward: bool,
    target: &mut [Vec<u32>],
    other: &[Vec<u32>],
    cap: u32,
    complete: &mut FixedBitSet,
) {
    // Coverage test for a node `w`: is `w` already covered w.r.t. `v`? i.e.
    // does `other[v]` ∩ `target[w]` already intersect? (For the forward pass
    // other=l_out, target=l_in: `v` reaches some landmark ℓ ∈ l_out[v], and
    // ℓ ∈ l_in[w], so `v` reaches `w` already — adding the `v` label is
    // redundant.) Kept as a free function so it takes only temporary borrows
    // and never conflicts with the mutable `target` write below.
    let mut stack = vec![v];
    let mut visited = FixedBitSet::with_capacity(dag.node_count() as usize);
    visited.insert(v as usize);
    while let Some(u) = stack.pop() {
        let neighbors = if forward { dag.out(u) } else { dag.rev(u) };
        for &w in neighbors {
            if visited.contains(w as usize) {
                continue;
            }
            if intersects(&other[v as usize], &target[w as usize]) {
                // Pruned: still mark visited so we don't re-test, but don't
                // expand and don't add the label.
                visited.insert(w as usize);
                continue;
            }
            visited.insert(w as usize);
            // Add v to target[w] (sorted insert; labels are built in landmark
            // order, which is not monotonic, so we sort on the fly).
            let slot = &mut target[w as usize];
            if slot.len() >= cap as usize {
                complete.set(w as usize, false);
                // Still expand — but don't store beyond cap. Expansion is what
                // propagates coverage to descendants.
            } else if let Err(pos) = slot.binary_search(&v) {
                slot.insert(pos, v);
            }
            stack.push(w);
        }
    }
}

/// Sorted-slice intersection test (early-exit).
fn intersects(a: &[u32], b: &[u32]) -> bool {
    let (mut i, mut j) = (0, 0);
    while i < a.len() && j < b.len() {
        match a[i].cmp(&b[j]) {
            std::cmp::Ordering::Less => i += 1,
            std::cmp::Ordering::Greater => j += 1,
            std::cmp::Ordering::Equal => return true,
        }
    }
    false
}

/// Bit-parallel BFS: propagate up to 64 source BFS frontiers in a single pass.
///
/// `reach[w]` bit `i` is set iff source `sources[i]` can reach `w` (via
/// out-edges). One traversal computes 64 reachability queries at once — with
/// 412 entry points that is 7 passes instead of 412.
///
/// Returns a `Vec<u64>` of length `dag.node_count()`.
pub fn bit_parallel_bfs(dag: &CsrGraph, sources: &[u32]) -> Vec<u64> {
    let n = dag.node_count() as usize;
    let mut reach = vec![0u64; n];
    if sources.is_empty() {
        return reach;
    }
    for chunk in sources.chunks(64) {
        let bit = 1u64;
        let mut frontier = vec![0u64; n];
        for (i, &s) in chunk.iter().enumerate() {
            if (s as usize) < n {
                frontier[s as usize] = bit << i;
                reach[s as usize] |= bit << i;
            }
        }
        loop {
            // Compute next frontier by OR-ing successors of all set bits.
            let mut next = vec![0u64; n];
            let mut any = false;
            for u in 0..n {
                let f = frontier[u];
                if f == 0 {
                    continue;
                }
                // Only the bits not yet reached at each successor.
                for &w in dag.out(u as u32) {
                    let new = f & !reach[w as usize];
                    if new != 0 {
                        next[w as usize] |= new;
                        any = true;
                    }
                }
            }
            if !any {
                break;
            }
            for w in 0..n {
                reach[w as usize] |= next[w as usize];
            }
            frontier = next;
        }
    }
    reach
}
