//! Near-duplicate collapse (§IV.8).
//!
//! The same pattern in 40 handlers is one finding with 40 sites, not 40
//! findings. Reviewer attention is the scarce resource. Shingle the
//! normalized span, MinHash to a `k`-permutation signature (Jaccard estimate,
//! SE ≈ 1/√k), then LSH-band into buckets whose collision probability is the
//! S-curve `1 − (1 − s^r)^b`, sharp at `≈ (1/b)^(1/r)`.

/// Split `text` into `w`-token shingles (whitespace tokens), each hashed.
pub fn shingle(text: &str, w: usize) -> Vec<u64> {
    let tokens: Vec<&str> = text.split_whitespace().collect();
    if tokens.len() < w {
        return tokens.iter().map(|t| hash_str(t)).collect();
    }
    (0..=tokens.len() - w)
        .map(|i| {
            let mut h = 0u64;
            for j in i..i + w {
                h = h.wrapping_mul(131).wrapping_add(hash_str(tokens[j]));
            }
            h
        })
        .collect()
}

/// MinHash signature of `k` permutations over the shingle set.
pub fn minhash(shingles: &[u64], k: usize) -> Vec<u64> {
    if shingles.is_empty() {
        return vec![u64::MAX; k];
    }
    (0..k)
        .map(|i| {
            let seed = (i as u64).wrapping_mul(0x9E3779B97F4A7C15).wrapping_add(0x1234567);
            shingles
                .iter()
                .map(|&s| splitmix64(s ^ seed))
                .min()
                .unwrap_or(u64::MAX)
        })
        .collect()
}

/// LSH banding: cluster indices whose signatures collide in at least one band.
/// `signature.len()` must equal `b * r`. Returns groups of input indices.
pub fn lsh_cluster(signatures: &[Vec<u64>], b: usize, r: usize) -> Vec<Vec<usize>> {
    let n = signatures.len();
    let mut parent: Vec<usize> = (0..n).collect();
    let find = |p: &mut Vec<usize>, x: usize| -> usize {
        let mut root = x;
        while p[root] != root {
            root = p[root];
        }
        let mut cur = x;
        while p[cur] != root {
            let nxt = p[cur];
            p[cur] = root;
            cur = nxt;
        }
        root
    };
    for band in 0..b {
        let mut buckets: rustc_hash::FxHashMap<u64, Vec<usize>> = rustc_hash::FxHashMap::default();
        for (idx, sig) in signatures.iter().enumerate() {
            let mut h = 0u64;
            for row in 0..r {
                let v = sig.get(band * r + row).copied().unwrap_or(0);
                h = h.wrapping_mul(137).wrapping_add(v);
            }
            buckets.entry(h).or_default().push(idx);
        }
        for (_, group) in buckets {
            let first = *group.first().unwrap();
            for &x in &group[1..] {
                let ra = find(&mut parent, first);
                let rb = find(&mut parent, x);
                if ra != rb {
                    parent[ra.max(rb)] = ra.min(rb);
                }
            }
        }
    }
    // Collect groups.
    let mut groups_map: rustc_hash::FxHashMap<usize, Vec<usize>> = rustc_hash::FxHashMap::default();
    for i in 0..n {
        let r = find(&mut parent, i);
        groups_map.entry(r).or_default().push(i);
    }
    groups_map.into_values().collect()
}

fn hash_str(s: &str) -> u64 {
    let mut h = 0xcbf29ce484222325u64;
    for b in s.bytes() {
        h = (h ^ b as u64).wrapping_mul(0x100000001b3);
    }
    h
}

fn splitmix64(z: u64) -> u64 {
    let z = z.wrapping_add(0x9E3779B97F4A7C15);
    let z = (z ^ (z >> 30)).wrapping_mul(0xBF58476D1CE4E5B9);
    let z = (z ^ (z >> 27)).wrapping_mul(0x94D049BB133111EB);
    z ^ (z >> 31)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn near_duplicates_cluster() {
        let a = "fn handle(req) { let x = req; x.unwrap() }";
        let b = "fn handle(req) { let x = req; x.unwrap() }"; // identical
        let c = "fn totally_different() { 42 }";
        let sigs: Vec<Vec<u64>> = [a, b, c]
            .iter()
            .map(|t| minhash(&shingle(t, 3), 128))
            .collect();
        let groups = lsh_cluster(&sigs, 20, 6);
        // a and b share a group; c is alone.
        let mut found_pair = false;
        for g in &groups {
            if g.contains(&0) && g.contains(&1) {
                found_pair = true;
            }
        }
        assert!(found_pair, "identical spans must cluster: {groups:?}");
        // c not clustered with a.
        for g in &groups {
            if g.contains(&0) {
                assert!(!g.contains(&2), "distinct span clustered with a: {g:?}");
            }
        }
    }

    #[test]
    fn minhash_estimates_jaccard() {
        let s1 = shingle("a b c d e f g h", 2);
        let s2 = shingle("a b c d e f g h i j", 2);
        let sig1 = minhash(&s1, 256);
        let sig2 = minhash(&s2, 256);
        let agree = sig1.iter().zip(&sig2).filter(|(x, y)| x == y).count() as f64;
        let est = agree / sig1.len() as f64;
        // True Jaccard of the shingle sets is ~0.6; estimate should be in range.
        assert!(est > 0.4 && est < 0.85, "minhash estimate {est} far from truth");
    }
}
