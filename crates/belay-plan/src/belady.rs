//! Offline caching: Belady MIN hint stream (§III.3).
//!
//! In a scan the future is fully known — we computed the schedule. That admits
//! the offline optimum: evict the block whose next use is furthest in the
//! future. Emit a `(block_hash, next_use_index)` hint alongside the schedule
//! so the router can honor it. If the router ignores hints, DFS order alone
//! makes LRU behave nearly like MIN under a tree walk.

/// For each position `i` in `schedule`, compute the next index `j > i` with the
/// same block hash (or `usize::MAX` if never reused). This is the Belady
/// eviction hint stream.
pub fn belady_hints(schedule: &[u64]) -> Vec<(u64, usize)> {
    let n = schedule.len();
    let mut out = Vec::with_capacity(n);
    for i in 0..n {
        let h = schedule[i];
        let next = schedule[i + 1..]
            .iter()
            .position(|&x| x == h)
            .map(|p| i + 1 + p)
            .unwrap_or(usize::MAX);
        out.push((h, next));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn next_use_indices() {
        // blocks: A B A C B  (indices 0..4)
        let sched = vec![1u64, 2, 1, 3, 2];
        let hints = belady_hints(&sched);
        // A@0 next used at 2; B@1 next at 4; A@2 never (MAX); C@3 never; B@4 never.
        assert_eq!(hints[0], (1, 2));
        assert_eq!(hints[1], (2, 4));
        assert_eq!(hints[2], (1, usize::MAX));
        assert_eq!(hints[3], (3, usize::MAX));
        assert_eq!(hints[4], (2, usize::MAX));
    }
}
