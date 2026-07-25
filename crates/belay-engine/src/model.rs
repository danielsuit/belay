//! The model abstraction (§I.5, §M6).
//!
//! A `Model` completes a prompt, optionally under a JSON schema (constrained
//! decoding via xgrammar on the serving path — valid by construction) and with
//! a set of tools. The engine drives pass 1 (stateless fan-out) and pass 2
//! (agentic, stateful, SPRT-terminated) against this trait. A `ScriptedModel`
//! lets tests run the full loop deterministically without a network.

use async_trait::async_trait;
use serde_json::Value;
use std::sync::Mutex;

/// A tool definition presented to the model.
#[derive(Clone, Debug)]
pub struct ToolDef {
    pub name: String,
    pub description: String,
    pub schema: Value,
}

/// A tool call the model issued.
#[derive(Clone, Debug)]
pub struct ToolCall {
    pub name: String,
    pub args: Value,
}

/// A request to the model.
#[derive(Clone, Debug)]
pub struct ModelRequest {
    pub prompt: String,
    pub schema: Option<Value>,
    pub tools: Vec<ToolDef>,
    pub max_tokens: u32,
}

/// A response: free content (which may embed a JSON judgment) plus tool calls.
#[derive(Clone, Debug, Default)]
pub struct ModelResponse {
    pub content: String,
    pub tool_calls: Vec<ToolCall>,
}

#[derive(Debug)]
pub struct ModelError(pub String);

/// The abstraction both passes run against.
#[async_trait]
pub trait Model: Send + Sync {
    async fn complete(&self, req: &ModelRequest) -> Result<ModelResponse, ModelError>;
}

/// A deterministic, in-process model for tests: returns canned responses in
/// order, ignoring inputs. The last response repeats.
pub struct ScriptedModel {
    responses: Mutex<Vec<ModelResponse>>,
}

impl ScriptedModel {
    pub fn new(responses: Vec<ModelResponse>) -> Self {
        Self {
            responses: Mutex::new(responses),
        }
    }
}

#[async_trait]
impl Model for ScriptedModel {
    async fn complete(&self, _req: &ModelRequest) -> Result<ModelResponse, ModelError> {
        let mut guard = self.responses.lock().unwrap();
        if guard.len() == 1 {
            return Ok(guard[0].clone());
        }
        Ok(guard.remove(0))
    }
}
