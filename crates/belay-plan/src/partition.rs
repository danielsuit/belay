//! Worker assignment (§III.4).
//!
//! When prefixes are shared (the trie's internal-node mass is significant),
//! partition the trie into `W` connected subtrees (on [`PromptTrie`]). When
//! sharing is low (< 20% of total mass) locality doesn't pay and plain LPT
//! list scheduling (Graham) is simpler and near-optimal on makespan.

use crate::trie::PromptTrie;

/// LPT list scheduling: assign chains (longest first) to the currently-least
/// loaded worker. Makespan ≤ (4/3 − 1/(3m))·OPT. Returns per-worker chain-id
/// lists. `weights[i]` = (chain_id, weight).
pub fn lpt(weights: &[(u32, u32)], w: usize) -> Vec<Vec<u32>> {
    if w == 0 {
        return vec![];
    }
    let mut order: Vec<usize> = (0..weights.len()).collect();
    order.sort_by_key(|&i| std::cmp::Reverse(weights[i].1));
    let mut loads = vec![0u32; w];
    let mut parts: Vec<Vec<u32>> = (0..w).map(|_| Vec::new()).collect();
    for i in order {
        let (id, wt) = weights[i];
        // least-loaded worker.
        let j = (0..w)
            .min_by_key(|&k| (loads[k], k))
            .unwrap_or(0);
        parts[j].push(id);
        loads[j] += wt;
    }
    parts.retain(|p| !p.is_empty());
    parts
}

/// Prefix-sharing coefficient: internal-node token mass / total mass. Below
/// ~0.20, locality doesn't pay — use LPT instead of a connected partition.
pub fn sharing_coefficient(trie: &PromptTrie, total: u32) -> f64 {
    if total == 0 {
        return 0.0;
    }
    let internal = trie.distinct_nodes() as f64 - 1.0; // token nodes
    internal / total as f64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lpt_balances_load() {
        let weights = vec![(0, 5), (1, 4), (2, 3), (3, 3), (4, 2)];
        let parts = lpt(&weights, 2);
        let loads: Vec<u32> = parts.iter().map(|p| p.iter().map(|&id| weights[id as usize].1).sum()).collect();
        let max = *loads.iter().max().unwrap();
        // OPT lower bound = ceil(17/2) = 9; LPT should be 9 or close.
        assert!(max <= 9 + 1);
        assert_eq!(loads.iter().sum::<u32>(), 17);
    }
}
