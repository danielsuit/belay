//! Near-duplicate collapse via MinHash + LSH banding (§IV.8).
//!
//! The same pattern in 40 handlers is one finding with 40 sites, not 40
//! findings. Shingle the normalized span, build a MinHash signature, band it
//! for LSH, cluster by union-find over candidate pairs above the Jaccard
//! threshold.

use rustc_hash::FxHashMap;
use std::collections::HashSet;

const MH_PRIME: u64 = 0xFFFF_FFFF_FFFF_FFC5; // a 64-bit prime-ish (Mersenne-adjacent)

/// Compute a MinHash signature of length `k` for a set of shingles (u64 hashes).
///
/// Uses `k` linear hash functions `h_i(x) = (a_i · x + b_i) mod prime`; the
/// signature element `i` is the minimum over all shingles. Standard error of
/// the Jaccard estimate is `1/√k` (≈0.088 at k=128).
pub fn minhash(shingles: &[u64], k: usize) -> Vec<u64> {
    if shingles.is_empty() {
        return vec![u64::MAX; k];
    }
    // Deterministic (a, b) pairs — splitmix over an index.
    let mut sig = vec![u64::MAX; k];
    for (i, s) in shingles.iter().enumerate() {
        for j in 0..k {
            let a = splitmix((j as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15) ^ 0xA5A5);
            let b = splitmix((j as u64).wrapping_add(0xC0FFEE));
            let h = (a.wrapping_mul(*s).wrapping_add(b) % MH_PRIME) ^ (i as u64); // mix shingle
            if h < sig[j] {
                sig[j] = h;
            }
        }
    }
    sig
}

/// Jaccard estimate from two MinHash signatures (fraction of matching rows).
pub fn jaccard_estimate(a: &[u64], b: &[u64]) -> f64 {
    debug_assert_eq!(a.len(), b.len());
    if a.is_empty() {
        return 0.0;
    }
    let m = a.iter().zip(b).filter(|(x, y)| x == y).count() as f64;
    m / a.len() as f64
}

/// Exact Jaccard of two shingle sets (used to confirm LSH candidate pairs).
pub fn jaccard_exact(a: &[u64], b: &[u64]) -> f64 {
    let sa: HashSet<u64> = a.iter().copied().collect();
    let sb: HashSet<u64> = b.iter().copied().collect();
    if sa.is_empty() && sb.is_empty() {
        return 1.0;
    }
    let inter = sa.intersection(&sb).count() as f64;
    let union = sa.union(&sb).count() as f64;
    inter / union
}

/// LSH banding: given `b` bands of `r` rows, returns the set of (i, j) index
/// pairs that collide in at least one band.
///
/// Collision probability is `1 − (1 − s^r)^b`, with a sharp S-curve at
/// `≈ (1/b)^(1/r)`. For target similarity 0.8: `r=5, b=20`.
pub fn lsh_candidates(signatures: &[Vec<u64>], r: usize, b: usize) -> Vec<(usize, usize)> {
    let k = r * b;
    let mut out = Vec::new();
    let mut seen: HashSet<(usize, usize)> = HashSet::new();
    for band in 0..b {
        let mut buckets: FxHashMap<u64, Vec<usize>> = FxHashMap::default();
        for (idx, sig) in signatures.iter().enumerate() {
            if sig.len() < k {
                continue;
            }
            let rows = &sig[band * r..(band + 1) * r];
            let key = band_hash(rows);
            buckets.entry(key).or_default().push(idx);
        }
        for members in buckets.values() {
            for i in 0..members.len() {
                for j in (i + 1)..members.len() {
                    let a = members[i].min(members[j]);
                    let c = members[i].max(members[j]);
                    if seen.insert((a, c)) {
                        out.push((a, c));
                    }
                }
            }
        }
    }
    out
}

fn band_hash(rows: &[u64]) -> u64 {
    let mut h = 0xCB_F2_9C_E4_84_22_FE_70_u64;
    for &x in rows {
        h ^= x;
        h = h.wrapping_mul(0x100_0000_01B3).wrapping_add(x);
    }
    h
}

/// Cluster signatures whose Jaccard estimate ≥ `sim_threshold`, via LSH
/// candidate generation + union-find. Returns cluster ids per signature.
pub fn cluster(signatures: &[Vec<u64>], r: usize, b: usize, sim_threshold: f64) -> Vec<usize> {
    let n = signatures.len();
    let mut parent: Vec<usize> = (0..n).collect();
    fn find(parent: &mut Vec<usize>, x: usize) -> usize {
        let mut root = x;
        while parent[root] != root {
            root = parent[root];
        }
        let mut cur = x;
        while parent[cur] != root {
            let nxt = parent[cur];
            parent[cur] = root;
            cur = nxt;
        }
        root
    }
    for (i, j) in lsh_candidates(signatures, r, b) {
        if jaccard_estimate(&signatures[i], &signatures[j]) >= sim_threshold {
            let ri = find(&mut parent, i);
            let rj = find(&mut parent, j);
            if ri != rj {
                parent[ri] = rj;
            }
        }
    }
    // Canonicalize: relabel roots to 0..k.
    let mut labels: Vec<usize> = vec![usize::MAX; n];
    let mut next = 0usize;
    let mut out = vec![0; n];
    for i in 0..n {
        let r = find(&mut parent, i);
        if labels[r] == usize::MAX {
            labels[r] = next;
            next += 1;
        }
        out[i] = labels[r];
    }
    out
}

/// Deterministic splitmix64 — no `Math::random` in the harness.
fn splitmix(mut z: u64) -> u64 {
    z = z.wrapping_add(0x9E37_79B9_7F4A_7C15);
    let mut z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}

/// A small helper to hash a token-shingle string to a u64.
pub fn shingle_hash(token: &str) -> u64 {
    let mut h = 0xCB_F2_9C_E4_84_22_FE_70_u64;
    for &b in token.as_bytes() {
        h ^= b as u64;
        h = h.wrapping_mul(0x100_0000_01B3).wrapping_add(b as u64);
    }
    if h == u64::MAX {
        1
    } else {
        h
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sig(s: &str, k: usize) -> Vec<u64> {
        let sh: Vec<u64> = s.split_whitespace().map(shingle_hash).collect();
        minhash(&sh, k)
    }

    #[test]
    fn identical_sets_have_unit_jaccard() {
        let a = sig("the quick brown fox", 128);
        let b = sig("the quick brown fox", 128);
        assert!((jaccard_estimate(&a, &b) - 1.0).abs() < 1e-9);
    }

    #[test]
    fn disjoint_sets_have_zero_jaccard() {
        let a = sig("the quick brown fox", 256);
        let b = sig("lazy dogs sleep now", 256);
        assert!(jaccard_estimate(&a, &b) < 0.1, "est={}", jaccard_estimate(&a, &b));
    }

    #[test]
    fn similar_sets_have_high_jaccard() {
        let a = sig("the quick brown fox jumps over the lazy dog", 256);
        let b = sig("the quick brown fox jumps over the lazy cat", 256);
        let est = jaccard_estimate(&a, &b);
        assert!(est > 0.5, "est={est}");
    }

    #[test]
    fn lsh_cluster_groups_duplicates() {
        let s1 = sig("a b c d e f g h", 128);
        let s2 = sig("a b c d e f g h", 128);
        let s3 = sig("x y z w q r s t", 128);
        let s4 = sig("x y z w q r s t", 128);
        let sigs = vec![s1, s2, s3, s4];
        let labels = cluster(&sigs, 4, 32, 0.8);
        assert_eq!(labels[0], labels[1], "duplicates 0,1 not grouped");
        assert_eq!(labels[2], labels[3], "duplicates 2,3 not grouped");
        assert_ne!(labels[0], labels[2]);
    }
}
