//! Call graph in CSR (compressed sparse row).
//!
//! Two `Vec<u32>` per direction: `offsets[n+1]` and `targets[m]`. BFS over CSR
//! is a linear scan of contiguous memory — the whole point versus an
//! adjacency `HashMap<SymbolId, Vec<SymbolId>>`, which is 20–40× slower to
//! traverse. Forward and reverse are both materialized: `callers_of` is just
//! a reverse-CSR scan.

use fixedbitset::FixedBitSet;

/// A directed graph stored in CSR over `u32` node ids.
///
/// Generic over the id type only for documentation; in practice we have one
/// over `SymbolId` (the call graph) and one over `NodeId` (the condensation).
#[derive(Clone, Debug, Default)]
pub struct CsrGraph {
    n: u32,
    pub offsets: Vec<u32>,
    pub targets: Vec<u32>,
    pub rev_offsets: Vec<u32>,
    pub rev_targets: Vec<u32>,
}

impl CsrGraph {
    /// Build a CSR graph from a sorted list of edges `(src, dst)`.
    ///
    /// Edges need not be sorted; we sort + dedup here. `n` is the node count;
    /// node ids are `0..n`.
    pub fn from_edges(n: u32, mut edges: Vec<(u32, u32)>) -> Self {
        edges.sort_unstable();
        edges.dedup();
        let m = edges.len();
        let mut offsets = vec![0u32; n as usize + 1];
        for &(s, _) in &edges {
            offsets[s as usize + 1] += 1;
        }
        for i in 0..n as usize {
            offsets[i + 1] += offsets[i];
        }
        let mut targets = vec![0u32; m];
        let mut cursor = offsets.clone();
        for &(s, d) in &edges {
            let pos = cursor[s as usize] as usize;
            targets[pos] = d;
            cursor[s as usize] += 1;
        }
        // Reverse CSR.
        let mut rev_counts = vec![0u32; n as usize];
        for &(_, d) in &edges {
            rev_counts[d as usize] += 1;
        }
        let mut rev_offsets = vec![0u32; n as usize + 1];
        for i in 0..n as usize {
            rev_offsets[i + 1] = rev_offsets[i] + rev_counts[i];
        }
        let mut rev_targets = vec![0u32; m];
        let mut rcursor = rev_offsets.clone();
        for &(s, d) in &edges {
            let pos = rcursor[d as usize] as usize;
            rev_targets[pos] = s;
            rcursor[d as usize] += 1;
        }
        Self {
            n,
            offsets,
            targets,
            rev_offsets,
            rev_targets,
        }
    }

    pub fn node_count(&self) -> u32 {
        self.n
    }

    pub fn edge_count(&self) -> usize {
        self.targets.len()
    }

    /// Out-edges of `s`. O(deg) contiguous slice.
    pub fn out(&self, s: u32) -> &[u32] {
        let start = self.offsets[s as usize] as usize;
        let end = self.offsets[s as usize + 1] as usize;
        &self.targets[start..end]
    }

    /// In-edges of `d` (callers, in the call graph). O(in-deg) contiguous slice.
    pub fn rev(&self, d: u32) -> &[u32] {
        let start = self.rev_offsets[d as usize] as usize;
        let end = self.rev_offsets[d as usize + 1] as usize;
        &self.rev_targets[start..end]
    }

    /// Out-degree.
    pub fn out_deg(&self, s: u32) -> usize {
        self.out(s).len()
    }

    /// Brute-force BFS reachability — the reference implementation.
    /// `reaches()` in [`crate::reach`] must agree with this.
    pub fn bfs_reachable(&self, from: u32, to: u32) -> bool {
        if from == to {
            return true;
        }
        let mut visited = FixedBitSet::with_capacity(self.n as usize);
        let mut stack = vec![from];
        visited.insert(from as usize);
        while let Some(u) = stack.pop() {
            for &v in self.out(u) {
                if v == to {
                    return true;
                }
                if !visited.put(v as usize) {
                    stack.push(v);
                }
            }
        }
        false
    }

    /// All nodes reachable from `from` (including `from` itself).
    pub fn reachable_set(&self, from: u32) -> FixedBitSet {
        let mut visited = FixedBitSet::with_capacity(self.n as usize);
        let mut stack = vec![from];
        visited.insert(from as usize);
        while let Some(u) = stack.pop() {
            for &v in self.out(u) {
                if !visited.put(v as usize) {
                    stack.push(v);
                }
            }
        }
        visited
    }

    /// Multi-source BFS: nodes reachable from *any* source.
    pub fn reachable_from_many(&self, sources: &[u32]) -> FixedBitSet {
        let mut visited = FixedBitSet::with_capacity(self.n as usize);
        let mut stack: Vec<u32> = Vec::with_capacity(sources.len());
        for &s in sources {
            if (s as usize) < self.n as usize && !visited.put(s as usize) {
                stack.push(s);
            }
        }
        while let Some(u) = stack.pop() {
            for &v in self.out(u) {
                if !visited.put(v as usize) {
                    stack.push(v);
                }
            }
        }
        visited
    }
}
