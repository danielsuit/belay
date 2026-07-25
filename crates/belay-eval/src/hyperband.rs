//! Successive halving / Hyperband (§VI.5) — prompt-variant selection under a
//! fixed eval budget. Quickly discards bad arms, spends the budget on the
//! promising ones.

/// Successive halving over precomputed per-resource scores.
/// `scores[arm][r]` is arm `arm`'s reward at resource level `r` (more resources
/// = more reliable estimate). Returns the index of the best arm.
pub fn successive_halving(scores: &[Vec<f64>], eta: f64) -> Option<usize> {
    let n = scores.len();
    if n == 0 {
        return None;
    }
    if n == 1 {
        return Some(0);
    }
    let levels = scores.iter().map(|s| s.len()).min().unwrap_or(1).max(1);
    let mut alive: Vec<usize> = (0..n).collect();
    let mut resource = 1usize;
    while alive.len() > 1 && resource <= levels {
        let r = resource.min(levels);
        let eval = |i: usize| scores[i][..r].iter().sum::<f64>() / r as f64;
        // Rank alive arms by mean reward, descending.
        alive.sort_by(|&a, &b| {
            eval(b).partial_cmp(&eval(a)).unwrap_or(std::cmp::Ordering::Equal)
        });
        let keep = ((alive.len() as f64) / eta).ceil() as usize;
        alive.truncate(keep.max(1));
        resource = ((resource as f64) * eta).round() as usize;
    }
    // Of the survivors, pick the highest mean over all levels.
    alive
        .into_iter()
        .max_by(|&a, &b| {
            let ea = scores[a].iter().sum::<f64>() / scores[a].len() as f64;
            let eb = scores[b].iter().sum::<f64>() / scores[b].len() as f64;
            ea.partial_cmp(&eb).unwrap_or(std::cmp::Ordering::Equal)
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn best_arm_is_selected() {
        // arm 2 is consistently best.
        let scores = vec![
            vec![0.3, 0.35, 0.33, 0.34],
            vec![0.5, 0.52, 0.51, 0.53],
            vec![0.8, 0.81, 0.82, 0.80],
            vec![0.2, 0.21, 0.19, 0.20],
        ];
        let best = successive_halving(&scores, 3.0);
        assert_eq!(best, Some(2));
    }

    #[test]
    fn empty_returns_none() {
        assert_eq!(successive_halving(&[], 3.0), None);
    }
}
