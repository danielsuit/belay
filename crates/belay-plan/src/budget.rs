//! Budgeted submodular coverage (§III.5).
//!
//! Under a token budget `B`, which chains do you scan? Coverage is monotone
//! submodular (the marginal value of a chain shrinks as related chains are
//! already selected), so greedy by marginal-gain-per-cost gives ½(1−1/e);
//! Sviridenko's variant reaches (1−1/e). Here we ship the density greedy with
//! **CELF lazy evaluation** (Leskovec et al.): submodularity means a stale
//! marginal gain is an upper bound, so a max-heap only re-evaluates at the top
//! — 100–700× fewer evaluations than the O(n²) plain greedy.

use rustc_hash::FxHashMap;
use std::cmp::Ordering;

/// A coverage item: a chain with a cost and the (weighted) elements it covers.
#[derive(Clone, Debug)]
pub struct Item {
    pub id: u32,
    pub cost: u32,
    pub covers: Vec<u32>,
}

/// Select items to maximize weighted coverage of their `covers` union under
/// `budget`, via CELF lazy-greedy density selection. Returns selected item ids
/// in selection order. `weights[e]` is the value of covering element `e`
/// (e.g. severity × prior).
pub fn budgeted_coverage(
    items: &[Item],
    weights: &FxHashMap<u32, f64>,
    budget: u32,
) -> Vec<u32> {
    if items.is_empty() || budget == 0 {
        return Vec::new();
    }
    let mut covered: FxHashMap<u32, f64> = FxHashMap::default();
    let mut selected: Vec<u32> = Vec::new();
    let mut spent = 0u32;
    let mut remaining: Vec<bool> = vec![true; items.len()];

    // Initial marginal gains.
    let mut heap: Vec<HeapEntry> = Vec::with_capacity(items.len());
    for (i, it) in items.iter().enumerate() {
        if it.cost == 0 || it.cost > budget {
            continue;
        }
        let g = marginal(it, &covered, weights);
        if g <= 0.0 {
            continue;
        }
        heap.push(HeapEntry { gain_per_cost: g / it.cost as f64, gain: g, idx: i });
    }
    // Max-heap by gain_per_cost, then gain, then idx (deterministic).
    heap.sort_by(|a, b| b.cmp(a));

    while let Some(top) = heap.first() {
        // If the best possible gain can't fit the remaining budget, stop.
        if spent + items[top.idx].cost > budget {
            // Remove this item (too costly now) and continue checking others.
            heap.remove(0);
            continue;
        }
        // Re-evaluate the top's gain lazily.
        let cur_gain = marginal(&items[top.idx], &covered, weights);
        let cur_dpc = cur_gain / items[top.idx].cost as f64;
        let still_top = heap.get(1).map(|s| s.gain_per_cost).unwrap_or(f64::NEG_INFINITY);
        if cur_dpc >= still_top || heap.len() == 1 {
            // Select it.
            let it = &items[top.idx];
            for e in &it.covers {
                let w = *weights.get(e).unwrap_or(&1.0);
                *covered.entry(*e).or_insert(0.0) += w;
            }
            selected.push(it.id);
            spent += it.cost;
            remaining[top.idx] = false;
            heap.remove(0);
        } else {
            // Reinsert with refreshed gain; re-sort.
            let mut e = heap.remove(0);
            e.gain = cur_gain;
            e.gain_per_cost = cur_dpc;
            let pos = heap.partition_point(|x| x.gain_per_cost > e.gain_per_cost);
            heap.insert(pos, e);
        }
    }
    let _ = remaining;
    selected
}

fn marginal(it: &Item, covered: &FxHashMap<u32, f64>, weights: &FxHashMap<u32, f64>) -> f64 {
    let mut g = 0.0;
    for e in &it.covers {
        let w = *weights.get(e).unwrap_or(&1.0);
        let already = *covered.get(e).unwrap_or(&0.0);
        // Element is "covered" once its accumulated weight >= its full weight.
        if already < w {
            g += w - already;
        }
    }
    g
}

#[derive(Clone, Copy)]
struct HeapEntry {
    gain_per_cost: f64,
    gain: f64,
    idx: usize,
}

impl PartialEq for HeapEntry {
    fn eq(&self, other: &Self) -> bool {
        self.gain_per_cost == other.gain_per_cost && self.gain == other.gain && self.idx == other.idx
    }
}
impl Eq for HeapEntry {}
impl PartialOrd for HeapEntry {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}
impl Ord for HeapEntry {
    fn cmp(&self, other: &Self) -> Ordering {
        self.gain_per_cost
            .partial_cmp(&other.gain_per_cost)
            .unwrap_or(Ordering::Equal)
            .then(self.gain.partial_cmp(&other.gain).unwrap_or(Ordering::Equal))
            .then(self.idx.cmp(&other.idx))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn weights(pairs: &[(u32, f64)]) -> FxHashMap<u32, f64> {
        pairs.iter().copied().collect()
    }

    #[test]
    fn respects_budget_and_is_monotone() {
        let items = vec![
            Item { id: 0, cost: 2, covers: vec![0, 1] },
            Item { id: 1, cost: 3, covers: vec![1, 2] },
            Item { id: 2, cost: 1, covers: vec![3] },
        ];
        let w = weights(&[(0, 1.0), (1, 1.0), (2, 1.0), (3, 1.0)]);
        let sel = budgeted_coverage(&items, &w, 3);
        let spent: u32 = sel.iter().map(|id| items.iter().find(|i| i.id == *id).unwrap().cost).sum();
        assert!(spent <= 3);
        // Coverage should be monotone non-decreasing as budget grows.
        let cov = |b: u32| -> f64 {
            let s = budgeted_coverage(&items, &w, b);
            let mut c = 0.0;
            let mut seen = std::collections::HashSet::new();
            for id in s {
                for e in &items.iter().find(|i| i.id == id).unwrap().covers {
                    if seen.insert(*e) {
                        c += *w.get(e).unwrap_or(&1.0);
                    }
                }
            }
            c
        };
        assert!(cov(1) <= cov(2));
        assert!(cov(2) <= cov(5));
        assert!(cov(5) <= cov(100));
    }

    #[test]
    fn celf_matches_naive_greedy() {
        // On this instance CELF and a plain O(n^2) density greedy pick the same.
        let items = vec![
            Item { id: 0, cost: 2, covers: vec![0, 1, 2] },
            Item { id: 1, cost: 2, covers: vec![2, 3] },
            Item { id: 2, cost: 1, covers: vec![4] },
            Item { id: 3, cost: 3, covers: vec![0, 4] },
        ];
        let w = weights(&[(0, 1.0), (1, 1.0), (2, 1.0), (3, 1.0), (4, 1.0)]);
        let celf = budgeted_coverage(&items, &w, 4);
        // Naive greedy for comparison.
        let mut covered: FxHashMap<u32, f64> = FxHashMap::default();
        let mut naive = Vec::new();
        let mut spent = 0u32;
        let mut avail: Vec<usize> = (0..items.len()).collect();
        while spent < 4 {
            let best = avail
                .iter()
                .copied()
                .filter(|&i| spent + items[i].cost <= 4)
                .max_by(|a, b| {
                    let ga = marginal(&items[*a], &covered, &w) / items[*a].cost as f64;
                    let gb = marginal(&items[*b], &covered, &w) / items[*b].cost as f64;
                    ga.partial_cmp(&gb).unwrap_or(Ordering::Equal)
                });
            match best {
                Some(i) => {
                    for e in &items[i].covers {
                        *covered.entry(*e).or_insert(0.0) += *w.get(e).unwrap_or(&1.0);
                    }
                    spent += items[i].cost;
                    naive.push(items[i].id);
                    avail.retain(|&x| x != i);
                }
                None => break,
            }
        }
        assert_eq!(celf, naive, "CELF must match naive density greedy");
    }
}
