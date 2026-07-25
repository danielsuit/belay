//! Fingerprint stability (§IV.9).
//!
//! Content-defined chunking (FastCDC) rather than fixed normalization: chunk
//! boundaries are determined by content, so inserting a line above the finding
//! shifts nothing downstream. Fixed-offset fingerprints break on every
//! reformat and make the baseline useless within a week.
//!
//! Three fingerprints per finding, matched in order: `(class, path, span)`
//! exact → `(class, span)` survives file moves → `(class, enclosing_symbol)`
//! survives edits within the function. We report the *weakest* match level used.

const MIN_CHUNK: usize = 64;
const MAX_CHUNK: usize = 4096;

/// A 256-entry gear table for FastCDC (deterministically generated).
fn gear_table() -> [u64; 256] {
    let mut t = [0u64; 256];
    let mut z = 0xDEADBEEFCAFEBABEu64;
    for e in t.iter_mut() {
        z = z.wrapping_add(0x9E3779B97F4A7C15);
        let mut a = (z ^ (z >> 30)).wrapping_mul(0xBF58476D1CE4E5B9);
        a = (a ^ (a >> 27)).wrapping_mul(0x94D049BB133111EB);
        *e = a ^ (a >> 31);
    }
    t
}

/// FastCDC content-defined chunking (Xia et al. 2016, gear hash). Returns
/// `(offset, length)` chunks covering all of `data`.
pub fn fastcdc(data: &[u8]) -> Vec<(usize, usize)> {
    let gear = gear_table();
    let mask: u64 = (1 << 9) - 1; // ~512-byte average chunk
    let mut chunks = Vec::new();
    let mut start = 0;
    while start < data.len() {
        let remaining = data.len() - start;
        if remaining <= MIN_CHUNK {
            chunks.push((start, remaining));
            break;
        }
        let mut fp = 0u64;
        let mut cut = None;
        // No cut in the first MIN_CHUNK bytes (skip).
        for i in MIN_CHUNK..remaining {
            fp = (fp << 1).wrapping_add(gear[data[start + i] as usize]);
            if i >= MAX_CHUNK {
                cut = Some(i);
                break;
            }
            if (fp & mask) == 0 {
                cut = Some(i + 1);
                break;
            }
        }
        let len = cut.unwrap_or(remaining);
        chunks.push((start, len));
        start += len;
    }
    chunks
}

/// Fingerprint a finding: blake3 over `class || rubric_version || <chunk hashes>`.
/// Content-defined chunking makes this stable against edits above the finding.
pub fn fingerprint(class: &str, rubric_version: &str, span_bytes: &[u8]) -> [u8; 16] {
    let chunks = fastcdc(span_bytes);
    let mut hasher = blake3::Hasher::new();
    hasher.update(class.as_bytes());
    hasher.update(&[0]);
    hasher.update(rubric_version.as_bytes());
    hasher.update(&[0]);
    for (off, len) in &chunks {
        let h = blake3::hash(&span_bytes[*off..*off + *len]);
        hasher.update(h.as_bytes());
    }
    let mut out = [0u8; 16];
    out.copy_from_slice(&hasher.finalize().as_bytes()[..16]);
    out
}

/// A baseline entry: one stored finding.
#[derive(Clone, Debug)]
pub struct BaselineEntry {
    pub class: String,
    pub path: String,
    pub span: (u32, u32),
    pub symbol: String,
    pub fp: [u8; 16],
}

/// Match a finding against the baseline, strongest level first.
/// Returns `(entry_index, level)` where level 1 = exact, 2 = span, 3 = symbol.
pub fn match_level(
    baseline: &[BaselineEntry],
    class: &str,
    path: &str,
    span: (u32, u32),
    symbol: &str,
) -> Option<(usize, u8)> {
    // Level 1: exact class + path + span.
    for (i, e) in baseline.iter().enumerate() {
        if e.class == class && e.path == path && e.span == span {
            return Some((i, 1));
        }
    }
    // Level 2: class + span (survives a file move).
    for (i, e) in baseline.iter().enumerate() {
        if e.class == class && e.span == span {
            return Some((i, 2));
        }
    }
    // Level 3: class + enclosing symbol (survives edits within the fn).
    for (i, e) in baseline.iter().enumerate() {
        if e.class == class && e.symbol == symbol {
            return Some((i, 3));
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fingerprint_is_deterministic_and_equal_for_identical() {
        let bytes = b"fn handle(req: u64) -> u64 { let x = req; x.unwrap() }";
        let a = fingerprint("panic-on-input", "v3", bytes);
        let b = fingerprint("panic-on-input", "v3", bytes);
        assert_eq!(a, b);
        // Different class → different fingerprint.
        let c = fingerprint("authz-missing", "v3", bytes);
        assert_ne!(a, c);
    }

    #[test]
    fn cdc_resynchronizes_after_a_prefix() {
        // With content-defined boundaries, chunking `data` should appear as a
        // suffix of chunking `prefix + data` once the gear hash resynchronizes.
        let data: Vec<u8> = (0..2000)
            .map(|i| ((i * 31) % 251) as u8)
            .collect();
        let prefix: Vec<u8> = (0..300).map(|i| ((i * 17) % 251) as u8).collect();
        let mut combined = prefix.clone();
        combined.extend_from_slice(&data);

        let chunks_data = fastcdc(&data);
        let chunks_combined = fastcdc(&combined);

        // The last chunk of `data` should appear (same content) near the end of
        // the combined chunking — i.e. CDC reconverged to data's boundaries.
        let last_data = chunks_data.last().unwrap();
        let mut found = false;
        for c in &chunks_combined {
            // Compare the chunk content (offset into the respective buffer).
            let d = &data[last_data.0..last_data.0 + last_data.1];
            if c.0 + c.1 <= combined.len() && c.1 == last_data.1 {
                let cc = &combined[c.0..c.0 + c.1];
                if cc == d {
                    found = true;
                    break;
                }
            }
        }
        assert!(found, "FastCDC did not resynchronize to data's last chunk");
    }

    #[test]
    fn match_level_reports_strongest_first() {
        let baseline = vec![BaselineEntry {
            class: "panic-on-input".into(),
            path: "src/a.rs".into(),
            span: (10, 20),
            symbol: "handle".into(),
            fp: [0; 16],
        }];
        // Exact.
        let m = match_level(&baseline, "panic-on-input", "src/a.rs", (10, 20), "handle");
        assert_eq!(m, Some((0, 1)));
        // File moved → level 2.
        let m = match_level(&baseline, "panic-on-input", "src/moved/a.rs", (10, 20), "handle");
        assert_eq!(m, Some((0, 2)));
        // Edited within fn (span changed) → level 3.
        let m = match_level(&baseline, "panic-on-input", "src/a.rs", (99, 111), "handle");
        assert_eq!(m, Some((0, 3)));
        // No match.
        let m = match_level(&baseline, "authz-missing", "src/a.rs", (10, 20), "handle");
        assert_eq!(m, None);
    }
}
