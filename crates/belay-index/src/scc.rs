//! Tarjan SCC + condensation.
//!
//! Call graphs have cycles (mutual recursion). Condense first: every SCC
//! becomes one node, and the condensation is a DAG. Reachability on the
//! condensation is both cheaper and semantically right — anything reachable
//! from one member of a recursive cluster is reachable from all.
//!
//! Iterative Tarjan to avoid blowing the stack on deep call chains.

use crate::graph::CsrGraph;

/// Result of condensing a graph: per-node SCC id and the DAG over SCCs.
#[derive(Clone, Debug)]
pub struct Condensation {
    /// `scc_of[node]` = SCC id in `0..scc_count`.
    pub scc_of: Vec<u32>,
    pub scc_count: u32,
    /// Condensation DAG (no cycles, no self-loops).
    pub dag: CsrGraph,
    /// Members of each SCC, for witnesses and slicing.
    pub members: Vec<Vec<u32>>,
}

/// Iterative Tarjan. Returns `scc_of` (one id per node) and `scc_count`.
///
/// Ids are assigned in *reverse topological order* of the condensation — a
/// sink SCC gets id 0 — which is a minor convenience for some downstream
/// traversals but not relied upon.
pub fn tarjan_scc(g: &CsrGraph) -> (Vec<u32>, u32) {
    let n = g.node_count() as usize;
    let mut index = vec![None; n];
    let mut lowlink = vec![0u32; n];
    let mut on_stack = fixedbitset::FixedBitSet::with_capacity(n);
    let mut stack: Vec<u32> = Vec::new();
    let mut scc_of = vec![0u32; n];
    let mut next_index = 0u32;
    let mut scc_count = 0u32;

    // Iterative DFS frame: (node, child-iterator-state = next child index).
    // `work` holds (node, neighbor_cursor) frames; we push children lazily.
    enum Frame {
        Enter(u32),
        Visit { node: u32, next: usize },
    }

    for root in 0..n as u32 {
        if index[root as usize].is_some() {
            continue;
        }
        let mut work: Vec<Frame> = vec![Frame::Enter(root)];
        while let Some(frame) = work.pop() {
            match frame {
                Frame::Enter(v) => {
                    index[v as usize] = Some(next_index);
                    lowlink[v as usize] = next_index;
                    next_index += 1;
                    stack.push(v);
                    on_stack.insert(v as usize);
                    work.push(Frame::Visit { node: v, next: 0 });
                }
                Frame::Visit { node, next } => {
                    let neighbors = g.out(node);
                    if next < neighbors.len() {
                        let w = neighbors[next];
                        // Re-push ourselves at next+1, then descend into w.
                        work.push(Frame::Visit { node, next: next + 1 });
                        match index[w as usize] {
                            None => work.push(Frame::Enter(w)),
                            Some(_) if on_stack.contains(w as usize) => {
                                let iw = index[w as usize].unwrap();
                                let lv = lowlink[node as usize];
                                lowlink[node as usize] = lv.min(iw);
                            }
                            _ => {}
                        }
                    } else {
                        // All neighbors processed: is `node` a root of an SCC?
                        if lowlink[node as usize] == index[node as usize].unwrap() {
                            loop {
                                let w = stack.pop().unwrap();
                                on_stack.remove(w as usize);
                                scc_of[w as usize] = scc_count;
                                if w == node {
                                    break;
                                }
                            }
                            scc_count += 1;
                        }
                        // Propagate lowlink to parent.
                        if let Some(Frame::Visit { node: parent, .. }) = work.last_mut() {
                            // Only propagate if the parent is still on stack
                            // (it always is here, since we're in its subtree).
                            let lp = lowlink[*parent as usize];
                            let lc = lowlink[node as usize];
                            lowlink[*parent as usize] = lp.min(lc);
                        }
                    }
                }
            }
        }
    }

    (scc_of, scc_count)
}

/// Condense `g` into its SCC DAG.
pub fn condense(g: &CsrGraph) -> Condensation {
    let n = g.node_count();
    let (scc_of, scc_count) = tarjan_scc(g);

    let mut members: Vec<Vec<u32>> = vec![Vec::new(); scc_count as usize];
    for node in 0..n {
        members[scc_of[node as usize] as usize].push(node);
    }

    // Collect inter-SCC edges, then dedup.
    let mut edges: Vec<(u32, u32)> = Vec::new();
    for u in 0..n {
        let su = scc_of[u as usize];
        for &v in g.out(u) {
            let sv = scc_of[v as usize];
            if su != sv {
                edges.push((su, sv));
            }
        }
    }
    let dag = CsrGraph::from_edges(scc_count, edges);

    Condensation {
        scc_of,
        scc_count,
        dag,
        members,
    }
}

impl Condensation {
    /// Map a node id to its SCC id.
    pub fn scc_of(&self, node: u32) -> u32 {
        self.scc_of[node as usize]
    }

    /// Is the condensation a true DAG? (Always true by construction; here for
    /// downstream assertions/tests.)
    pub fn is_acyclic(&self) -> bool {
        for n in 0..self.scc_count {
            for &v in self.dag.out(n) {
                if v == n {
                    return false;
                }
            }
        }
        true
    }
}
