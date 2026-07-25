//! HTTP model client — the real `Model` over a Subconscious/OpenAI-compatible
//! serving path (§I.1, §III.7).
//!
//! Constrained decoding is the serving path's job (xgrammar against the JSON
//! schema); we pass `response_format: { type: "json_schema", schema }` when a
//! schema is supplied so output is valid by construction, never valid-on-retry.
//! This is not exercised by unit tests (it needs a live endpoint) but is the
//! production wiring the CLI uses.

use async_trait::async_trait;
use crate::model::{Model, ModelError, ModelRequest, ModelResponse, ToolCall};
use serde_json::{json, Value};

pub struct HttpModel {
    client: reqwest::Client,
    base_url: String,
    model: String,
    api_key: Option<String>,
}

impl HttpModel {
    pub fn new(base_url: impl Into<String>, model: impl Into<String>, api_key: Option<String>) -> Self {
        Self {
            client: reqwest::Client::new(),
            base_url: base_url.into(),
            model: model.into(),
            api_key,
        }
    }
}

#[async_trait]
impl Model for HttpModel {
    async fn complete(&self, req: &ModelRequest) -> Result<ModelResponse, ModelError> {
        let mut body = json!({
            "model": self.model,
            "messages": [{"role": "user", "content": req.prompt}],
            "temperature": 0,
            "max_tokens": req.max_tokens,
        });
        if let Some(schema) = &req.schema {
            body["response_format"] = json!({ "type": "json_schema", "json_schema": { "name": "out", "schema": schema } });
        }
        if !req.tools.is_empty() {
            body["tools"] = json!(req.tools.iter().map(|t| json!({
                "type": "function",
                "function": { "name": t.name, "description": t.description, "parameters": t.schema }
            })).collect::<Vec<_>>());
        }

        let mut r = self.client.post(format!("{}/chat/completions", self.base_url.trim_end_matches('/')));
        if let Some(key) = &self.api_key {
            r = r.bearer_auth(key);
        }
        let resp = r.json(&body).send().await.map_err(|e| ModelError(e.to_string()))?;
        let v: Value = resp.json().await.map_err(|e| ModelError(e.to_string()))?;
        let choice = v.get("choices").and_then(|c| c.get(0)).ok_or_else(|| ModelError("no choices".into()))?;
        let msg = choice.get("message").ok_or_else(|| ModelError("no message".into()))?;
        let content = msg.get("content").and_then(|c| c.as_str()).unwrap_or("").to_string();
        let mut tool_calls = Vec::new();
        if let Some(tcs) = msg.get("tool_calls").and_then(|x| x.as_array()) {
            for tc in tcs {
                if let (Some(name), Some(args)) = (
                    tc.get("function").and_then(|f| f.get("name")).and_then(|n| n.as_str()),
                    tc.get("function").and_then(|f| f.get("arguments")).and_then(|a| a.as_str()),
                ) {
                    let args: Value = serde_json::from_str(args).unwrap_or(json!({}));
                    tool_calls.push(ToolCall { name: name.to_string(), args });
                }
            }
        }
        Ok(ModelResponse { content, tool_calls })
    }
}
