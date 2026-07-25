//! belay-taint: IFDS interprocedural taint + a generic monotone dataflow
//! solver + Steensgaard aliasing (§II.4, §II.5).
//!
//! "Do not send the model anything the static layer can already rule out."
//! A slice with no taint path from any source to any sink is never a scan
//! candidate — pruning it costs microseconds instead of 6k tokens.

pub mod lattice;
pub mod steensgaard;
pub mod taint;

pub use lattice::{solve_forward, Cfg, Lattice, SetLattice};
pub use steensgaard::Steensgaard;
pub use taint::{reachable_functions, Flow, Function, Operand, SinkSite, Source, Stmt, TaintProblem, Var};
