//! Offline caching: Belady hint stream (§III.3).
//!
//! In a scan the future is fully known — the schedule was computed in
//! §III.2 — so the offline optimum (Belady's MIN: evict the block whose next
//! use is furthest) is available. We emit a `(block, next_use_index)` hint
//! stream alongside the scan order for the router to honor. If the router
//! ignores hints, DFS order alone gets most of the benefit: under a tree
//! walk, LRU ≈ MIN (the least-recently-used block genuinely is the
//! furthest-future one).

/// For each position `(i, j)` in the emission — chain `i`, block `paths[i][j]`
/// — the index of the next chain `k > i` that reuses that block, or `None` if
/// never reused. This is exactly the Belady "next use" signal.
pub fn next_use(paths: &[Vec<u32>]) -> Vec<Vec<Option<usize>>> {
    let n = paths.len();
    let mut out: Vec<Vec<Option<usize>>> = (0..n).map(|_| Vec::new()).collect();
    for i in 0..n {
        for (_, &block) in paths[i].iter().enumerate() {
            let mut nxt = None;
            for k in (i + 1)..n {
                if paths[k].contains(&block) {
                    nxt = Some(k);
                    break;
                }
            }
            out[i].push(nxt);
        }
    }
    out
}

/// Belady eviction hint at a given step: among the currently-resident blocks,
/// the one whose next use is furthest (or `None`-valued) is the evict
/// candidate. Returns that block id.
pub fn belady_evict_candidate(
    resident: &[(u32, Option<usize>)], // (block, next_use)
) -> Option<u32> {
    resident
        .iter()
        .max_by_key(|(_, nu)| match nu {
            Some(k) => *k,
            None => usize::MAX,
        })
        .map(|(b, _)| *b)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn next_use_finds_reuse() {
        // chain 0 path [A,B,C]; chain 1 path [A,B,D]; A and B reused at 1, C not.
        let paths = vec![vec![0, 1, 2], vec![0, 1, 3]];
        let nu = next_use(&paths);
        assert_eq!(nu[0][0], Some(1)); // A reused by chain 1
        assert_eq!(nu[0][1], Some(1)); // B reused by chain 1
        assert_eq!(nu[0][2], None); // C never reused
        assert_eq!(nu[1][0], None); // A reused by nobody after chain 1
    }

    #[test]
    fn belady_picks_furthest_or_never() {
        let resident = vec![(0u32, Some(5)), (1u32, Some(2)), (2u32, None)];
        // block 2 has no next use (None -> furthest); evict it.
        assert_eq!(belady_evict_candidate(&resident), Some(2));
    }
}
