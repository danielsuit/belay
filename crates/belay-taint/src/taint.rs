//! IFDS interprocedural taint (§II.4).
//!
//! Reps–Horwitz–Sagiv: interprocedural, finite, distributive subset problems as
//! graph reachability on an *exploded supergraph*, O(E·D³). Taint is exactly
//! such a problem — the domain is the finite set of tracked facts, transfers
//! are distributive. We solve it as a worklist reachability over exploded
//! nodes `(cfg_node, fact)`.
//!
//! Soundness contract: a slice with no taint path from any source to any sink
//! is never a scan candidate. This is the single largest cost multiplier in
//! the design, and it is free relative to a token — pruning a non-candidate
//! costs microseconds, not 6k tokens.

use rustc_hash::{FxHashMap, FxHashSet};

/// A variable id (global, unique across the workspace model).
pub type Var = u32;
/// A function id.
pub type Func = u32;

/// An operand: a variable or a constant.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Operand {
    Var(Var),
    Const,
}

/// A statement in the small taint IR. The CFG is linear (statements in order)
/// within a function; branches are not modeled (over-approximation is sound).
#[derive(Clone, Debug)]
pub enum Stmt {
    /// `dst = src` (or `dst = <const>`).
    Assign { dst: Var, src: Operand },
    /// `dst? = callee(args)` — interprocedural call.
    Call {
        dst: Option<Var>,
        callee: Func,
        args: Vec<Operand>,
    },
    /// A sink: reports if `val` is tainted at this point.
    Sink { val: Operand },
    /// `return val`.
    Return { val: Operand },
    /// A sanitizer: taint of `var` is killed here (allow-list).
    Sanitize { var: Var },
    /// No-op / pass-through.
    Nop,
}

/// A function in the model.
#[derive(Clone, Debug)]
pub struct Function {
    pub id: Func,
    pub params: Vec<Var>,
    pub body: Vec<Stmt>,
}

/// One taint source: a variable that is tainted at a function's entry.
#[derive(Clone, Debug)]
pub struct Source {
    pub func: Func,
    pub var: Var,
}

/// One sink: a `Stmt::Sink` occurrence (identified by function + statement index).
#[derive(Clone, Debug)]
pub struct SinkSite {
    pub func: Func,
    pub stmt: usize,
}

/// The interprocedural taint problem.
pub struct TaintProblem {
    pub functions: Vec<Function>,
    pub sources: Vec<Source>,
    pub sinks: Vec<SinkSite>,
}

/// A confirmed taint flow: source → sink, with a witness path of (func, stmt) steps.
#[derive(Clone, Debug)]
pub struct Flow {
    pub source: Source,
    pub sink: SinkSite,
    /// Witness: ordered list of (function, statement index) on the path.
    pub witness: Vec<(Func, usize)>,
}

/// Node in the per-function linear CFG = statement index; a synthetic
/// "exit" node sits at `body.len()`.
fn func_exit(f: &Function) -> usize {
    f.body.len()
}

impl TaintProblem {
    fn func(&self, id: Func) -> &Function {
        &self.functions[id as usize]
    }

    /// Solve: return all confirmed source→sink flows.
    ///
    /// Context-insensitive (facts are bare var ids, not per-call-context). For
    /// taint *reachability* this is sound (over-approximation): if any call
    /// makes a sink reachable, we report it. It can over-report (a tainted
    /// return from one call site seeding another), which is the precision
    /// cost the model layer refines away — never a false negative.
    pub fn solve(&self) -> Vec<Flow> {
        // reachable: (func, stmt_index, tainted_var) — the fact holds at the
        // INPUT of that statement. We also track the exit node via stmt_index
        // == body.len().
        let mut reachable: FxHashSet<(Func, usize, Var)> = FxHashSet::default();
        let mut parent: FxHashMap<(Func, usize, Var), (Func, usize, Var)> = FxHashMap::default();
        let mut worklist: Vec<(Func, usize, Var)> = Vec::new();

        // Seed sources at each function's entry.
        for s in &self.sources {
            let key = (s.func, 0, s.var);
            if reachable.insert(key) {
                worklist.push(key);
                parent.insert(key, key);
            }
        }

        // Precompute call sites grouped by callee for return-edge seeding.
        let mut callsites: Vec<Vec<(Func, usize)>> = Vec::new(); // callee -> list of (caller_func, call_stmt_idx)
        for f in &self.functions {
            if callsites.len() <= f.id as usize {
                callsites.resize_with(f.id as usize + 1, Vec::new);
            }
        }
        for f in &self.functions {
            for (i, stmt) in f.body.iter().enumerate() {
                if let Stmt::Call { callee, .. } = stmt {
                    callsites[*callee as usize].push((f.id, i));
                }
            }
        }

        while let Some((func, idx, var)) = worklist.pop() {
            let f = self.func(func);
            // If at exit node, propagate to all caller successors' return-dst.
            if idx == func_exit(f) {
                // For each call site calling `func`, find the return var and
                // seed the call's successor with TaintedVar(dst).
                for &(caller, call_idx) in &callsites[func as usize] {
                    let cf = self.func(caller);
                    if let Stmt::Call { dst: Some(dst), .. } = &cf.body[call_idx] {
                        // The return var of `func` is its Return stmt's val.
                        if let Some(ret_var) = self.return_var(func) {
                            if var == ret_var {
                                let succ = call_idx + 1;
                                let key = (caller, succ, *dst);
                                if reachable.insert(key) {
                                    parent.insert(key, (func, idx, var));
                                    worklist.push(key);
                                }
                            }
                        }
                    }
                }
                continue;
            }

            let stmt = &f.body[idx];
            let next = idx + 1;

            // Compute the outgoing facts for this statement from the incoming
            // fact `var` (distributive transfer).
            let produced: Vec<Var> = match stmt {
                Stmt::Assign { dst, src } => {
                    let mut out = Vec::new();
                    // propagate vars that aren't the killed dst
                    if var != *dst {
                        out.push(var);
                    }
                    // gen: if src is the tainted var, dst becomes tainted
                    if let Operand::Var(s) = src {
                        if var == *s {
                            out.push(*dst);
                        }
                    }
                    out
                }
                Stmt::Sanitize { var: v } => {
                    // kill taint on v; propagate others
                    if var == *v {
                        Vec::new()
                    } else {
                        vec![var]
                    }
                }
                Stmt::Sink { .. } | Stmt::Nop => {
                    vec![var]
                }
                Stmt::Return { .. } => {
                    // The return var's taint is picked up at the exit node via
                    // the return-var check below; also propagate to exit.
                    vec![var]
                }
                Stmt::Call { args, .. } => {
                    // Pass tainted args to the callee entry.
                    for (i, arg) in args.iter().enumerate() {
                        if let Operand::Var(a) = arg {
                            if var == *a {
                                let callee = match stmt {
                                    Stmt::Call { callee, .. } => *callee,
                                    _ => unreachable!(),
                                };
                                let cf = self.func(callee);
                                if let Some(&param) = cf.params.get(i) {
                                    let key = (callee, 0, param);
                                    if reachable.insert(key) {
                                        parent.insert(key, (func, idx, var));
                                        worklist.push(key);
                                    }
                                }
                            }
                        }
                    }
                    // After the call, args remain tainted (over-approx; sound).
                    vec![var]
                }
            };

            for out_var in produced {
                // Propagate to the next node (or exit).
                let key = (func, next, out_var);
                if reachable.insert(key) {
                    parent.insert(key, (func, idx, var));
                    worklist.push(key);
                }
            }

            // If this statement is a Return, also propagate to the exit node
            // carrying the return var (so callers can map it to their dst).
            if let Stmt::Return { val: Operand::Var(rv) } = stmt {
                if var == *rv {
                    let key = (func, func_exit(f), *rv);
                    if reachable.insert(key) {
                        parent.insert(key, (func, idx, var));
                        worklist.push(key);
                    }
                }
            }
        }

        // Collect flows: any reachable (func, stmt, var) where stmt is a Sink
        // and var == the sink's var.
        let mut flows = Vec::new();
        for sink in &self.sinks {
            let f = self.func(sink.func);
            if let Stmt::Sink { val: Operand::Var(sv) } = &f.body[sink.stmt] {
                if reachable.contains(&(sink.func, sink.stmt, *sv)) {
                    // Walk the parent chain to the seeded source (self-loop root).
                    let witness = self.reconstruct(&parent, sink.func, sink.stmt, *sv);
                    if let Some(source) = self.source_from_root(&parent, sink.func, sink.stmt, *sv) {
                        flows.push(Flow { source, sink: sink.clone(), witness });
                    }
                }
            }
        }
        flows
    }

    /// Walk the parent chain to its self-loop root and match it against a
    /// seeded source (sources are seeded at `(func, 0, var)` with parent = self).
    fn source_from_root(
        &self,
        parent: &FxHashMap<(Func, usize, Var), (Func, usize, Var)>,
        func: Func,
        stmt: usize,
        var: Var,
    ) -> Option<Source> {
        let mut cur = (func, stmt, var);
        for _ in 0..100_000 {
            match parent.get(&cur) {
                Some(&p) if p != cur => cur = p,
                _ => break,
            }
        }
        self.sources
            .iter()
            .find(|s| s.func == cur.0 && s.var == cur.2)
            .cloned()
    }

    fn return_var(&self, func: Func) -> Option<Var> {
        let f = self.func(func);
        f.body.iter().rev().find_map(|s| match s {
            Stmt::Return { val: Operand::Var(v) } => Some(*v),
            _ => None,
        })
    }

    fn reconstruct(
        &self,
        parent: &FxHashMap<(Func, usize, Var), (Func, usize, Var)>,
        func: Func,
        stmt: usize,
        var: Var,
    ) -> Vec<(Func, usize)> {
        let mut path = vec![(func, stmt)];
        let mut cur = (func, stmt, var);
        for _ in 0..10_000 {
            match parent.get(&cur) {
                Some(&p) if p != cur => {
                    path.push((p.0, p.1));
                    cur = p;
                }
                _ => break,
            }
        }
        path.reverse();
        path
    }
}

/// The set of taint-reachable functions (those that ever hold a tainted fact).
/// Used by the planner to prune non-candidates before any model call.
pub fn reachable_functions(tp: &TaintProblem) -> FxHashSet<Func> {
    let flows = tp.solve();
    let mut set = FxHashSet::default();
    for f in &flows {
        set.insert(f.source.func);
        set.insert(f.sink.func);
        for (func, _) in &f.witness {
            set.insert(*func);
        }
    }
    set
}

#[cfg(test)]
mod tests {
    use super::*;

    fn var(name: &str, map: &mut Vec<String>) -> Var {
        if let Some(i) = map.iter().position(|n| n == name) {
            return i as Var;
        }
        map.push(name.to_string());
        (map.len() - 1) as Var
    }

    #[test]
    fn intraprocedural_taint_reaches_sink() {
        // fn f(req) { let x = req; sink(x); }
        let mut names = Vec::new();
        let req = var("req", &mut names);
        let x = var("x", &mut names);
        let f = Function {
            id: 0,
            params: vec![req],
            body: vec![
                Stmt::Assign { dst: x, src: Operand::Var(req) },
                Stmt::Sink { val: Operand::Var(x) },
                Stmt::Return { val: Operand::Var(x) },
            ],
        };
        let tp = TaintProblem {
            functions: vec![f],
            sources: vec![Source { func: 0, var: req }],
            sinks: vec![SinkSite { func: 0, stmt: 1 }],
        };
        let flows = tp.solve();
        assert_eq!(flows.len(), 1);
        assert_eq!(flows[0].sink.stmt, 1);
    }

    #[test]
    fn sanitizer_cuts_the_flow() {
        // fn f(req) { sanitize(req); sink(req); } -> NO flow
        let mut names = Vec::new();
        let req = var("req", &mut names);
        let f = Function {
            id: 0,
            params: vec![req],
            body: vec![
                Stmt::Sanitize { var: req },
                Stmt::Sink { val: Operand::Var(req) },
                Stmt::Return { val: Operand::Var(req) },
            ],
        };
        let tp = TaintProblem {
            functions: vec![f],
            sources: vec![Source { func: 0, var: req }],
            sinks: vec![SinkSite { func: 0, stmt: 1 }],
        };
        let flows = tp.solve();
        assert!(flows.is_empty(), "sanitizer should cut the flow");
    }

    #[test]
    fn interprocedural_taint_through_call() {
        // fn helper(p) { sink(p); return p; }
        // fn f(req) { let r = helper(req); sink(r); }
        let mut names = Vec::new();
        let req = var("req", &mut names);
        let p = var("p", &mut names);
        let r = var("r", &mut names);
        let helper = Function {
            id: 1,
            params: vec![p],
            body: vec![
                Stmt::Sink { val: Operand::Var(p) },   // stmt 0: sink in helper
                Stmt::Return { val: Operand::Var(p) },
            ],
        };
        let f = Function {
            id: 0,
            params: vec![req],
            body: vec![
                Stmt::Call { dst: Some(r), callee: 1, args: vec![Operand::Var(req)] }, // stmt 0
                Stmt::Sink { val: Operand::Var(r) },   // stmt 1: sink of return taint
                Stmt::Return { val: Operand::Var(r) },
            ],
        };
        let tp = TaintProblem {
            functions: vec![f, helper],
            sources: vec![Source { func: 0, var: req }],
            sinks: vec![
                SinkSite { func: 1, stmt: 0 },
                SinkSite { func: 0, stmt: 1 },
            ],
        };
        let flows = tp.solve();
        // Both sinks reachable.
        assert!(flows.iter().any(|fl| fl.sink.func == 1 && fl.sink.stmt == 0));
        assert!(flows.iter().any(|fl| fl.sink.func == 0 && fl.sink.stmt == 1));
    }

    #[test]
    fn untainted_path_is_not_reported() {
        // fn f(req) { let safe = const; sink(safe); } -> NO flow (safe not tainted)
        let mut names = Vec::new();
        let req = var("req", &mut names);
        let safe = var("safe", &mut names);
        let f = Function {
            id: 0,
            params: vec![req],
            body: vec![
                Stmt::Assign { dst: safe, src: Operand::Const },
                Stmt::Sink { val: Operand::Var(safe) },
                Stmt::Return { val: Operand::Var(req) },
            ],
        };
        let tp = TaintProblem {
            functions: vec![f],
            sources: vec![Source { func: 0, var: req }],
            sinks: vec![SinkSite { func: 0, stmt: 1 }],
        };
        let flows = tp.solve();
        assert!(flows.is_empty(), "untainted path should not be reported");
    }
}
