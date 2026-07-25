//! Steensgaard pointer analysis (§II.5) — unification-based, ~O(n·α(n)).
//!
//! Rust's `&mut` exclusivity means an active mutable borrow has no other live
//! alias, so the points-to sets that blow up in C are already constrained by
//! the borrow checker. Steensgaard-level unification is adequate for
//! `&`/`&mut`/`Box`; residual imprecision concentrates in `Rc<RefCell<_>>`,
//! raw pointers, and `unsafe` — exactly where we *want* over-approximation
//! (route to the model rather than silently drop).

/// A union-find over variable/pointer equivalence classes.
#[derive(Clone, Debug)]
pub struct Steensgaard {
    parent: Vec<u32>,
    rank: Vec<u8>,
}

impl Steensgaard {
    pub fn new() -> Self {
        Self {
            parent: Vec::new(),
            rank: Vec::new(),
        }
    }

    /// Add a node (returns its id).
    pub fn add_node(&mut self) -> u32 {
        let id = self.parent.len() as u32;
        self.parent.push(id);
        self.rank.push(0);
        id
    }

    pub fn ensure(&mut self, id: u32) {
        if self.parent.len() <= id as usize {
            while self.parent.len() <= id as usize {
                self.add_node();
            }
        }
    }

    /// Find the representative with path halving.
    pub fn find(&mut self, x: u32) -> u32 {
        self.ensure(x);
        let mut cur = x;
        while self.parent[cur as usize] != cur {
            let p = self.parent[cur as usize];
            self.parent[cur as usize] = self.parent[p as usize]; // path halving
            cur = p;
        }
        cur
    }

    /// Unify the points-to sets of `a` and `b` (Steensgaard's unification rule:
    /// `a = &b` ⟹ pts(a) = pts(b)).
    pub fn unify(&mut self, a: u32, b: u32) {
        let ra = self.find(a);
        let rb = self.find(b);
        if ra == rb {
            return;
        }
        // union by rank
        if self.rank[ra as usize] < self.rank[rb as usize] {
            self.parent[ra as usize] = rb;
        } else if self.rank[ra as usize] > self.rank[rb as usize] {
            self.parent[rb as usize] = ra;
        } else {
            self.parent[rb as usize] = ra;
            self.rank[ra as usize] += 1;
        }
    }

    /// `a` and `b` may alias (same equivalence class).
    pub fn may_alias(&mut self, a: u32, b: u32) -> bool {
        self.find(a) == self.find(b)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unify_merges_classes() {
        let mut s = Steensgaard::new();
        let a = s.add_node();
        let b = s.add_node();
        let c = s.add_node();
        s.unify(a, b);
        assert!(s.may_alias(a, b));
        assert!(!s.may_alias(a, c));
        s.unify(b, c);
        assert!(s.may_alias(a, c)); // transitive
    }
}
