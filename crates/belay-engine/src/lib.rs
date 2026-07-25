//! belay-engine: the two-pass scan loop (§M4, §M6).
//!
//! Pass 1 — stateless fan-out, one call per chain against the candidate schema,
//! span-verified or discarded. Pass 2 — agentic refutation over five read-only
//! tools, terminated by the SPRT/e-process (§IV.2); candidates investigated in
//! Weitzman order (§III.6). The model is abstracted behind [`model::Model`] so
//! the full loop runs deterministically under a [`model::ScriptedModel`] in
//! tests, and over an HTTP serving path in production via [`client::HttpModel`].

pub mod client;
pub mod engine;
pub mod finding;
pub mod model;
pub mod prompt;
pub mod sprt;
pub mod verify;
pub mod weitzman;

pub use client::HttpModel;
pub use engine::{execute_tool, pass1, pass2, tool_defs, Pass2Outcome, Slice};
pub use finding::{Finding, Severity};
pub use model::{Model, ModelError, ModelRequest, ModelResponse, ScriptedModel, ToolCall, ToolDef};
pub use prompt::{candidate_schema, frozen_prefix, rubric_for};
pub use sprt::{Accumulator, Decision};
pub use verify::{verify_finding, verify_span, RawFinding};
pub use weitzman::{order as weitzman_order, Pandora, reservation_value};
