//! A generic monotone dataflow solver — the `MonotoneSolver<L>` shape shared
//! by every dataflow pass (§II.4).
//!
//! Implements Kleene iteration to the least fixed point (Knaster–Tarski):
//! the lattice is finite and transfers are monotone, so iteration terminates.
//! The same engine backs the reaching-`unsafe` analysis and the
//! panic-reachability analysis; IFDS taint (§II.4) is the interprocedural
//! reachability specialization in [`crate::taint`].

use fixedbitset::FixedBitSet;

/// A bounded-height lattice with a bottom, join, and order.
pub trait Lattice: Clone {
    fn bottom(universe: usize) -> Self;
    fn join(&self, other: &Self) -> Self;
    fn less_equal(&self, other: &Self) -> bool;
    fn universe(&self) -> usize;
}

/// A set lattice over a finite universe (2^U, ⊆, ∪) — the shape of reaching
/// definitions, live variables, taint fact-sets, etc.
#[derive(Clone, Debug, Default)]
pub struct SetLattice(FixedBitSet);

impl SetLattice {
    pub fn from_bits(b: FixedBitSet) -> Self {
        Self(b)
    }
    pub fn bits(&self) -> &FixedBitSet {
        &self.0
    }
    pub fn insert(&mut self, i: usize) {
        self.0.insert(i);
    }
    pub fn contains(&self, i: usize) -> bool {
        self.0.contains(i)
    }
}

impl Lattice for SetLattice {
    fn bottom(universe: usize) -> Self {
        Self(FixedBitSet::with_capacity(universe))
    }
    fn join(&self, other: &Self) -> Self {
        let mut b = self.0.clone();
        b.union_with(&other.0);
        Self(b)
    }
    fn less_equal(&self, other: &Self) -> bool {
        self.0.is_subset(&other.0)
    }
    fn universe(&self) -> usize {
        self.0.len()
    }
}

/// A control-flow graph: `succ[node]` is the list of successors and
/// `pred[node]` the list of predecessors, kept as a reverse-adjacency list so
/// IN-sets can be computed in O(in-deg) rather than by scanning every node
/// (§II.2 CSR/reverse philosophy).
#[derive(Clone, Debug)]
pub struct Cfg {
    pub entry: usize,
    pub succ: Vec<Vec<usize>>,
    pub pred: Vec<Vec<usize>>,
}

impl Cfg {
    pub fn new(entry: usize, n: usize) -> Self {
        Self {
            entry,
            succ: vec![Vec::new(); n],
            pred: vec![Vec::new(); n],
        }
    }
    pub fn add_edge(&mut self, u: usize, v: usize) {
        self.succ[u].push(v);
        self.pred[v].push(u);
    }
    pub fn n(&self) -> usize {
        self.succ.len()
    }
}

/// Forward monotone dataflow to the least fixed point (MFP).
///
/// `init` seeds nodes with extra facts (e.g. entry with sources). `transfer`
/// is the per-node monotone transfer function. Returns the OUT set per node.
pub fn solve_forward<L: Lattice>(
    cfg: &Cfg,
    universe: usize,
    init: &[(usize, L)],
    transfer: impl Fn(usize, &L) -> L,
) -> Vec<L> {
    let n = cfg.n();
    let mut out: Vec<L> = (0..n).map(|_| L::bottom(universe)).collect();
    let mut in_: Vec<L> = (0..n).map(|_| L::bottom(universe)).collect();
    // Seed.
    let mut seeds = vec![None; n];
    for (node, val) in init {
        let slot = seeds[*node].get_or_insert_with(|| L::bottom(universe));
        *slot = slot.join(val);
    }

    let mut worklist: Vec<usize> = (0..n).collect();
    while let Some(u) = worklist.pop() {
        // IN[u] = seed[u] ⊔ join of OUT[pred] over predecessors (O(in-deg(u))).
        let mut inu = L::bottom(universe);
        if let Some(seed) = &seeds[u] {
            inu = inu.join(seed);
        }
        for &pred in &cfg.pred[u] {
            inu = inu.join(&out[pred]);
        }
        in_[u] = inu.clone();
        let new_out = transfer(u, &inu);
        if !new_out.less_equal(&out[u]) || !out[u].less_equal(&new_out) {
            // changed
            out[u] = new_out;
            for &v in &cfg.succ[u] {
                worklist.push(v);
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Reaching-definitions on a straight-line + branch CFG.
    /// defs: d0 at node0 (x=1), d1 at node1 (x=2), d2 at node3 (x=3).
    /// A def of x kills prior defs of x.
    fn idx(b: &FixedBitSet) -> Vec<usize> {
        b.ones().collect()
    }

    #[test]
    fn reaching_definitions_fixedpoint() {
        // 0: x=1 (def0, kills def1,def2)  -> 1
        // 1: x=2 (def1)                  -> 2
        // 2: sink                        -> 3
        // 3: x=3 (def2)                  -> (end)
        let mut cfg = Cfg::new(0, 4);
        cfg.add_edge(0, 1);
        cfg.add_edge(1, 2);
        cfg.add_edge(2, 3);
        let universe = 3; // defs 0,1,2
        let transfer = |node: usize, inn: &SetLattice| -> SetLattice {
            let mut out = inn.clone();
            match node {
                0 => {
                    out.insert(0);
                }
                1 => {
                    out.insert(1);
                }
                3 => {
                    out.insert(2);
                }
                _ => {}
            }
            out
        };
        let out = solve_forward(&cfg, universe, &[], transfer);
        // node0 out: {0}; node1 in {0} -> out {0,1}; node2 out {0,1}; node3 out {0,1,2}
        assert_eq!(idx(out[0].bits()), vec![0]);
        assert_eq!(idx(out[1].bits()), vec![0, 1]);
        assert_eq!(idx(out[2].bits()), vec![0, 1]);
        assert_eq!(idx(out[3].bits()), vec![0, 1, 2]);
    }
}
