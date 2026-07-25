//! Pass 1 (stateless fan-out) and pass 2 (agentic, SPRT-terminated) — §M4, §M6.
//!
//! Pass 1: one call per chain against the candidate schema → raw findings →
//! span-verified or discarded. Pass 2: a refutation loop over the five
//! read-only tools, accumulating evidence into the SPRT/e-process until a
//! boundary or the cost cap. The order candidates are paid for is Weitzman's
//! (§III.6); which tool to call next is the adaptive-submodular hint (§IV.3).

use crate::model::{Model, ModelRequest, ToolCall, ToolDef};
use crate::prompt::{self, parse_judgment};
use crate::sprt::{Accumulator, Decision};
use crate::verify::{verify_finding, RawFinding};
use belay_index::{FileId, Index, Span};
use serde_json::{json, Value};

/// A scan slice: the text sent to the model in pass 1, plus its location for
/// span verification.
#[derive(Clone, Debug)]
pub struct Slice {
    pub class: String,
    pub file: FileId,
    /// Byte span of this slice within the file.
    pub span: Span,
    pub text: String,
}

/// The five read-only tools (§I.5).
pub fn tool_defs() -> Vec<ToolDef> {
    vec![
        ToolDef {
            name: "read_span".into(),
            description: "Read a byte span of a file.".into(),
            schema: json!({"type":"object","properties":{"path":{"type":"string"},"start":{"type":"integer"},"end":{"type":"integer"}},"required":["path","start","end"]}),
        },
        ToolDef {
            name: "definition_of".into(),
            description: "Find the defining symbol of a name.".into(),
            schema: json!({"type":"object","properties":{"symbol":{"type":"string"}},"required":["symbol"]}),
        },
        ToolDef {
            name: "callers_of".into(),
            description: "Direct callers of a symbol.".into(),
            schema: json!({"type":"object","properties":{"symbol":{"type":"string"}},"required":["symbol"]}),
        },
        ToolDef {
            name: "reaches".into(),
            description: "Is `from` reachable to `to`? Returns a witness path if so.".into(),
            schema: json!({"type":"object","properties":{"from":{"type":"string"},"to":{"type":"string"}},"required":["from","to"]}),
        },
        ToolDef {
            name: "grep".into(),
            description: "Escape hatch: substring/pattern search.".into(),
            schema: json!({"type":"object","properties":{"pattern":{"type":"string"},"glob":{"type":"string"}},"required":["pattern"]}),
        },
    ]
}

/// Execute a tool call against the index. All read-only, all O(1)-ish.
pub fn execute_tool(index: &Index, call: &ToolCall) -> Value {
    match call.name.as_str() {
        "read_span" => {
            let path = call.args.get("path").and_then(|v| v.as_str()).unwrap_or("");
            let start = call.args.get("start").and_then(|v| v.as_u64()).unwrap_or(0) as u32;
            let end = call.args.get("end").and_then(|v| v.as_u64()).unwrap_or(0) as u32;
            match find_file(index, path) {
                Some(file) => {
                    let span = Span { file, start, end };
                    json!({ "ok": true, "text": index.read_span(&span) })
                }
                None => json!({ "ok": false, "error": "file not found" }),
            }
        }
        "definition_of" => {
            let sym = call.args.get("symbol").and_then(|v| v.as_str()).unwrap_or("");
            match index.definition_of(sym) {
                Some(id) => json!({ "ok": true, "id": id, "qual": index.qual(id), "name": index.name(id) }),
                None => json!({ "ok": false }),
            }
        }
        "callers_of" => {
            let sym = call.args.get("symbol").and_then(|v| v.as_str()).unwrap_or("");
            match index.definition_of(sym) {
                Some(id) => {
                    let callers: Vec<String> = index.callers_of(id).iter().map(|&c| index.qual(c).to_string()).collect();
                    json!({ "ok": true, "callers": callers })
                }
                None => json!({ "ok": false }),
            }
        }
        "reaches" => {
            let from = call.args.get("from").and_then(|v| v.as_str()).unwrap_or("");
            let to = call.args.get("to").and_then(|v| v.as_str()).unwrap_or("");
            match (index.definition_of(from), index.definition_of(to)) {
                (Some(f), Some(t)) => {
                    let path: Vec<String> = index
                        .witness(f, t)
                        .unwrap_or_default()
                        .iter()
                        .map(|&s| index.qual(s).to_string())
                        .collect();
                    json!({ "ok": true, "reaches": index.reaches(f, t), "witness": path })
                }
                _ => json!({ "ok": false }),
            }
        }
        "grep" => {
            let pat = call.args.get("pattern").and_then(|v| v.as_str()).unwrap_or("");
            let mut hits = Vec::new();
            for f in &index.sources.files {
                if let Ok(text) = std::str::from_utf8(&f.bytes) {
                    for (i, line) in text.lines().enumerate() {
                        if line.contains(pat) {
                            hits.push(json!({ "path": f.rel_path, "line": i + 1 }));
                        }
                    }
                }
            }
            json!({ "ok": true, "hits": hits })
        }
        _ => json!({ "ok": false, "error": "unknown tool" }),
    }
}

fn find_file(index: &Index, path: &str) -> Option<FileId> {
    index
        .sources
        .files
        .iter()
        .find(|f| f.rel_path == path || f.path.ends_with(path))
        .map(|f| f.id)
}

/// Pass 1: produce span-verified raw findings from a set of slices.
pub async fn pass1(
    index: &Index,
    rubric_version: &str,
    slices: &[Slice],
    model: &dyn Model,
) -> Vec<RawFinding> {
    let prefix = prompt::frozen_prefix(rubric_version);
    let schema = prompt::candidate_schema();
    let mut out = Vec::new();
    for sl in slices {
        let prompt = prompt::assemble_pass1(&prefix, &sl.class, &sl.text);
        let req = ModelRequest {
            prompt,
            schema: Some(schema.clone()),
            tools: Vec::new(),
            max_tokens: 2048,
        };
        let resp = match model.complete(&req).await {
            Ok(r) => r,
            Err(_) => continue,
        };
        // Parse candidate JSON from the content.
        if let Some(findings) = parse_findings(&resp.content) {
            for f in findings {
                let start = sl.span.start + f.start_byte;
                let end = sl.span.start + f.end_byte;
                let raw = RawFinding {
                    class: f.class,
                    rubric_version: rubric_version.to_string(),
                    file: sl.file,
                    span: Span { file: sl.file, start, end },
                    cited_snippet: f.cited_snippet,
                    confidence: f.confidence,
                    rationale: f.rationale,
                };
                if let Some(verified) = verify_finding(index, &raw) {
                    out.push(verified);
                }
            }
        }
    }
    out
}

struct ParsedFinding {
    class: String,
    start_byte: u32,
    end_byte: u32,
    cited_snippet: String,
    confidence: f64,
    rationale: String,
}

fn parse_findings(content: &str) -> Option<Vec<ParsedFinding>> {
    let start = content.find('{')?;
    let end = content.rfind('}')? + 1;
    let v: Value = serde_json::from_str(&content[start..end]).ok()?;
    let arr = v.get("findings")?.as_array()?;
    let mut out = Vec::new();
    for f in arr {
        out.push(ParsedFinding {
            class: f.get("class")?.as_str()?.to_string(),
            start_byte: f.get("start_byte")?.as_u64()? as u32,
            end_byte: f.get("end_byte")?.as_u64()? as u32,
            cited_snippet: f.get("cited_snippet")?.as_str()?.to_string(),
            confidence: f.get("confidence")?.as_f64().unwrap_or(0.0),
            rationale: f.get("rationale").and_then(|x| x.as_str()).unwrap_or("").to_string(),
        });
    }
    Some(out)
}

/// Pass-2 outcome.
#[derive(Clone, Debug)]
pub struct Pass2Outcome {
    pub decision: Decision,
    pub p: f64,
    pub turns: u32,
}

/// Pass 2: agentic refutation of one candidate, SPRT-terminated.
///
/// The model may call tools (executed against the index) or emit a judgment
/// `{"verdict":"vuln|benign","p":P(vuln)}`. Each judgment is fed to the
/// accumulator; the loop stops at a boundary or the cost cap.
pub async fn pass2(
    index: &Index,
    rubric_version: &str,
    candidate: &RawFinding,
    model: &dyn Model,
    alpha: f64,
    beta: f64,
) -> Pass2Outcome {
    let prefix = prompt::frozen_prefix(rubric_version);
    let rubric = prompt::rubric_for(&candidate.class);
    let tools = tool_defs();
    let mut acc = Accumulator::new(alpha, beta);
    let mut history = String::new();
    history.push_str(&format!(
        "{prefix}\n{rubric}\n\nInvestigate this candidate finding. Call tools to\n\
         refute it, then emit a JSON judgment {{\"verdict\":\"vuln|benign\",\"p\":P(vuln)}}.\n\n\
         Candidate: class={class} confidence={conf:.3}\nRationale: {rationale}\n",
        class = candidate.class,
        conf = candidate.confidence,
        rationale = candidate.rationale,
    ));

    let mut last_p = candidate.confidence;
    loop {
        let req = ModelRequest {
            prompt: history.clone(),
            schema: None,
            tools: tools.clone(),
            max_tokens: 1024,
        };
        let resp = match model.complete(&req).await {
            Ok(r) => r,
            Err(_) => break,
        };
        if !resp.tool_calls.is_empty() {
            for call in &resp.tool_calls {
                let result = execute_tool(index, call);
                history.push_str(&format!(
                    "\nTool {} -> {}\n",
                    call.name,
                    serde_json::to_string(&result).unwrap_or_default()
                ));
            }
            continue;
        }
        if let Some(j) = parse_judgment(&resp.content) {
            let p = j.p.clamp(0.0001, 0.9999);
            last_p = p;
            let llr = (p / (1.0 - p)).ln();
            let e = (p / (1.0 - p)).max(0.0);
            let dec = acc.observe(llr, e);
            history.push_str(&format!(
                "\nJudgment: {:?} p={:.3} -> {:?}\n",
                j.verdict, p, dec
            ));
            if dec != Decision::Continue {
                return Pass2Outcome { decision: dec, p: last_p, turns: acc.turns() };
            }
        }
        if acc.turns() >= acc.turn_cap {
            break;
        }
    }
    Pass2Outcome {
        decision: acc.decide(),
        p: last_p,
        turns: acc.turns(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{ModelResponse, ScriptedModel};
    use std::fs;
    use tempfile::tempdir;

    fn gateway_index() -> (tempfile::TempDir, Index, Slice) {
        let dir = tempdir().unwrap();
        let path = dir.path().join("src/handler.rs");
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        let code = "fn handle(req: u64) -> u64 { let x = req; x.unwrap_me() }\n";
        fs::write(&path, code).unwrap();
        let idx = Index::build(dir.path());
        let sym = idx.symbols.iter().find(|s| s.kind == belay_index::SymbolKind::Fn).unwrap();
        let text = idx.read_span(&sym.span).to_string();
        let slice = Slice {
            class: "panic-on-input".into(),
            file: sym.file,
            span: sym.span,
            text,
        };
        (dir, idx, slice)
    }

    #[tokio::test]
    async fn pass1_verifies_grounded_candidate() {
        let (_dir, idx, slice) = gateway_index();
        // Model cites the exact `x.unwrap_me()` substring with correct offsets.
        let snippet = "x.unwrap_me()";
        let start_byte = slice.text.find(snippet).unwrap() as u32;
        let end_byte = start_byte + snippet.len() as u32;
        let content = format!(
            "{{\"findings\":[{{\"class\":\"panic-on-input\",\"start_byte\":{start},\"end_byte\":{end},\"cited_snippet\":\"{snippet}\",\"confidence\":0.8,\"rationale\":\"unwrap on tainted\"}}]}}",
            start = start_byte,
            end = end_byte,
        );
        let model = ScriptedModel::new(vec![ModelResponse { content, tool_calls: vec![] }]);
        let findings = pass1(&idx, "v3", &[slice], &model).await;
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].class, "panic-on-input");
    }

    #[tokio::test]
    async fn pass1_discards_ungrounded_candidate() {
        let (_dir, idx, slice) = gateway_index();
        // Model cites a snippet that isn't in the file.
        let content = "{\"findings\":[{\"class\":\"panic-on-input\",\"start_byte\":0,\"end_byte\":5,\"cited_snippet\":\"TOTALLY_MADE_UP\",\"confidence\":0.8,\"rationale\":\"x\"}]}";
        let model = ScriptedModel::new(vec![ModelResponse { content: content.into(), tool_calls: vec![] }]);
        let findings = pass1(&idx, "v3", &[slice], &model).await;
        assert!(findings.is_empty(), "ungrounded candidate must be discarded");
    }

    #[tokio::test]
    async fn pass2_accepts_on_vuln_judgment() {
        let (_dir, idx, slice) = gateway_index();
        let raw = RawFinding {
            class: "panic-on-input".into(),
            rubric_version: "v3".into(),
            file: slice.file,
            span: slice.span,
            cited_snippet: slice.text.clone(),
            confidence: 0.8,
            rationale: "unwrap on req-derived".into(),
        };
        // Turn 0: a tool call (reaches). Turn 1: a vuln judgment p=0.95.
        let model = ScriptedModel::new(vec![
            ModelResponse {
                content: "".into(),
                tool_calls: vec![ToolCall { name: "reaches".into(), args: json!({"from":"handle","to":"unwrap_me"}) }],
            },
            ModelResponse {
                content: "{\"verdict\":\"vuln\",\"p\":0.95,\"note\":\"refutation failed\"}".into(),
                tool_calls: vec![],
            },
        ]);
        let out = pass2(&idx, "v3", &raw, &model, 0.05, 0.05).await;
        assert_eq!(out.decision, Decision::Accept);
        assert!(out.turns <= 2);
    }

    #[tokio::test]
    async fn pass2_rejects_on_benign_judgment() {
        let (_dir, idx, slice) = gateway_index();
        let raw = RawFinding {
            class: "panic-on-input".into(),
            rubric_version: "v3".into(),
            file: slice.file,
            span: slice.span,
            cited_snippet: slice.text.clone(),
            confidence: 0.5,
            rationale: "x".into(),
        };
        let model = ScriptedModel::new(vec![ModelResponse {
            content: "{\"verdict\":\"benign\",\"p\":0.05,\"note\":\"sanitized\"}".into(),
            tool_calls: vec![],
        }]);
        let out = pass2(&idx, "v3", &raw, &model, 0.05, 0.05).await;
        assert_eq!(out.decision, Decision::Reject);
    }
}

