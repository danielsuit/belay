//! The prompt trie and DFS-optimality (§III.2).
//!
//! Chains overlap at their heads — many handlers funnel into the same
//! middleware, the same auth check. Build a trie over their token sequences;
//! emit in DFS pre-order and the total prefill is exactly the number of
//! distinct trie nodes — the information-theoretic minimum. A bad order pays
//! up to Σ|path|. Scan order is a tree traversal, not a loop over files.

/// A scan chain: a token sequence with a cost and the (symbol, class) pairs it
/// covers. `tokens` is the shared-structure key the trie is built over.
#[derive(Clone, Debug)]
pub struct Chain {
    pub id: u32,
    pub tokens: Vec<u32>,
    /// Prefill cost in tokens (distinct-token mass of this chain in isolation).
    pub cost: u32,
    /// (symbol, taint-class) pairs this chain covers — for budgeted coverage.
    pub covers: Vec<u32>,
}

#[derive(Clone, Debug, Default)]
struct TrieNode {
    token: Option<u32>,
    children: Vec<TrieNode>,
    /// Chain ending at this node, if any.
    chain: Option<u32>,
}

impl TrieNode {
    fn insert(&mut self, tokens: &[u32], chain_id: u32) {
        if tokens.is_empty() {
            self.chain = Some(chain_id);
            return;
        }
        let head = tokens[0];
        if let Some(child) = self.children.iter_mut().find(|c| c.token == Some(head)) {
            child.insert(&tokens[1..], chain_id);
        } else {
            let mut child = TrieNode { token: Some(head), ..Default::default() };
            child.insert(&tokens[1..], chain_id);
            self.children.push(child);
        }
    }

    fn distinct_nodes(&self) -> usize {
        1 + self.children.iter().map(|c| c.distinct_nodes()).sum::<usize>()
    }

    /// Chain ids in DFS pre-order (the scan order).
    fn dfs_leaves(&self, out: &mut Vec<u32>) {
        if let Some(id) = self.chain {
            out.push(id);
        }
        for c in &self.children {
            c.dfs_leaves(out);
        }
    }
}

/// The prompt trie over a set of chains.
#[derive(Clone, Debug, Default)]
pub struct PromptTrie {
    root: TrieNode,
}

impl PromptTrie {
    pub fn build(chains: &[Chain]) -> Self {
        let mut trie = PromptTrie::default();
        for c in chains {
            trie.root.insert(&c.tokens, c.id);
        }
        trie
    }

    /// Number of distinct trie nodes (root + every token node). Under DFS with
    /// a cache holding the longest path, this is the minimum total prefill.
    pub fn distinct_nodes(&self) -> usize {
        self.root.distinct_nodes()
    }

    /// The naive prefill: every chain paid in full, no sharing.
    pub fn naive_prefill(chains: &[Chain]) -> u32 {
        chains.iter().map(|c| c.cost).sum()
    }

    /// DFS pre-order of chain ids — the scan order that achieves the minimum.
    pub fn dfs_order(&self) -> Vec<u32> {
        let mut out = Vec::new();
        self.root.dfs_leaves(&mut out);
        out
    }

    pub fn root_children_count(&self) -> usize {
        self.root.children.len()
    }

    /// Balanced connected k-partition of the trie into `w` connected subtrees
    /// (§III.4). Each part is a set of chain ids forming a connected subtree;
    /// the shared ancestor path is resident on exactly the workers that need
    /// it. Bottom-up greedy (cut when accumulated weight ≥ total/w), a
    /// 2-approximation of the min-max bound. `cost(id)` gives a chain's weight.
    pub fn partition(&self, cost: &dyn Fn(u32) -> u32, w: usize) -> Vec<Vec<u32>> {
        if w == 0 {
            return vec![];
        }
        let total: u32 = self.root.subtree_leaf_cost(cost);
        if total == 0 {
            return vec![];
        }
        let target = (total + w as u32 - 1) / w as u32; // ceil(total/w)
        let mut parts: Vec<Vec<u32>> = Vec::new();
        let (cw, cl) = part_sub(&self.root, cost, target, &mut parts);
        if cw > 0 {
            parts.push(cl);
        }
        // Merge the smallest parts until we have at most w (merging can break
        // connectedness but keeps the balance bound).
        while parts.len() > w {
            parts.sort_by_key(|p| p.len());
            let smallest = parts.remove(0);
            parts[0].extend(smallest);
        }
        parts.retain(|p| !p.is_empty());
        parts
    }
}

impl TrieNode {
    fn subtree_leaf_cost(&self, cost: &dyn Fn(u32) -> u32) -> u32 {
        let mut s = self.chain.map(cost).unwrap_or(0);
        for c in &self.children {
            s += c.subtree_leaf_cost(cost);
        }
        s
    }
}

/// Returns (carried_weight, carried_leaves) for the uncut portion of `node`.
fn part_sub(
    node: &TrieNode,
    cost: &dyn Fn(u32) -> u32,
    target: u32,
    parts: &mut Vec<Vec<u32>>,
) -> (u32, Vec<u32>) {
    let mut acc_w = node.chain.map(cost).unwrap_or(0);
    let mut acc_leaves: Vec<u32> = node.chain.into_iter().collect();
    for child in &node.children {
        let (cw, cl) = part_sub(child, cost, target, parts);
        if cw == 0 {
            continue;
        }
        if cw >= target {
            // Child carried a chunk ≥ target up — cut it as its own part.
            parts.push(cl);
        } else {
            acc_w = acc_w.saturating_add(cw);
            acc_leaves.extend(cl);
        }
    }
    if acc_w >= target {
        parts.push(acc_leaves);
        (0, vec![])
    } else {
        (acc_w, acc_leaves)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn chain(id: u32, tokens: &[u32], cost: u32) -> Chain {
        Chain { id, tokens: tokens.to_vec(), cost, covers: vec![] }
    }

    #[test]
    fn dfs_order_is_preorder_and_prefill_is_distinct_nodes() {
        // a->b->{c,d}, a->e
        let chains = vec![
            chain(0, &[1, 2, 3], 3),
            chain(1, &[1, 2, 4], 3),
            chain(2, &[1, 5], 2),
        ];
        let trie = PromptTrie::build(&chains);
        assert_eq!(trie.dfs_order(), vec![0, 1, 2]);
        // distinct nodes = root + a + b + c + d + e = 6.
        assert_eq!(trie.distinct_nodes(), 6);
        // DFS prefill (token nodes only) = 5; naive = 8.
        assert_eq!(trie.distinct_nodes() - 1, 5);
        assert_eq!(PromptTrie::naive_prefill(&chains), 8);
    }

    #[test]
    fn no_sharing_means_dfs_equals_naive() {
        let chains = vec![chain(0, &[1, 2], 2), chain(1, &[3, 4], 2)];
        let trie = PromptTrie::build(&chains);
        assert_eq!(trie.distinct_nodes() - 1, 4);
        assert_eq!(PromptTrie::naive_prefill(&chains), 4);
    }
}
