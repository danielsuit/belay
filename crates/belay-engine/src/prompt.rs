//! Prompt assembly (§III.2, §IV.0).
//!
//! A frozen system + taxonomy prefix shared across every scan; a per-class
//! rubric paragraph + one positive/one negative exemplar; then the chain
//! content. The prefix is frozen so it caches as one block and is re-warmed at
//! session start (§V.1). Constrained decoding (xgrammar) against the candidate
//! schema makes pass-1 output valid by construction.

use serde_json::{json, Value};

/// The frozen system + taxonomy prefix (versioned — §IV.0 edits invalidate
/// every cached prefix and stored calibration, so the version is recorded in
/// every finding).
pub fn frozen_prefix(rubric_version: &str) -> String {
    format!(
        "You are belay, a read-only Rust security scanner. Read-only: you may only\n\
         call the provided tools. Report only findings grounded in verified file\n\
         bytes; if you cannot cite a span that matches the source, report nothing.\n\
         Rubric version: {rubric_version}.\n\
         Taxonomy: tenant-isolation, cache-poisoning, authz-missing,\n\
         accounting-integrity, inflight-race, resource-unbounded, panic-on-input,\n\
         unsafe-soundness, ssrf-upstream, secret-exposure, injection, deser-bomb.\n"
    )
}

/// A per-class rubric paragraph (the rubric is the product — §IV.0).
pub fn rubric_for(class: &str) -> String {
    match class {
        "tenant-isolation" => format!(
            "{class}: a cache key, radix key, or routing decision that is not\n\
             scoped by tenant/org, so one tenant's request can read or poison\n\
             another's data. Positive: a key built from user input without the\n\
             tenant id. Negative: a key prefixed with the authenticated tenant id."
        ),
        "panic-on-input" => format!(
            "{class}: `unwrap`/`expect`/index/slice on request-derived data, so\n\
             attacker input can panic the worker. Positive: `headers[\"x\"].unwrap()`\n\
             on a request header. Negative: `headers.get(\"x\").ok_or(...)?`."
        ),
        other => format!(
            "{other}: report only if you can cite the exact span and explain the\n\
             attacker-reachable path to the sink."
        ),
    }
}

/// Assemble a pass-1 prompt for a chain: frozen prefix + rubric + chain bytes.
pub fn assemble_pass1(prefix: &str, class: &str, chain_text: &str) -> String {
    format!("{prefix}\n{}\n\nSource:\n```\n{chain_text}\n```\n", rubric_for(class))
}

/// The JSON schema for a pass-1 candidate (constrained-decoding target).
pub fn candidate_schema() -> Value {
    json!({
        "type": "object",
        "properties": {
            "findings": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "class": { "type": "string" },
                        "start_byte": { "type": "integer" },
                        "end_byte": { "type": "integer" },
                        "cited_snippet": { "type": "string" },
                        "confidence": { "type": "number" },
                        "rationale": { "type": "string" }
                    },
                    "required": ["class", "start_byte", "end_byte", "cited_snippet", "confidence", "rationale"]
                }
            }
        },
        "required": ["findings"]
    })
}

/// A pass-2 judgment the model emits when it has decided.
#[derive(Clone, Debug)]
pub struct Judgment {
    pub verdict: Verdict,
    /// Calibrated P(vuln | evidence).
    pub p: f64,
    pub note: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Verdict {
    Vuln,
    Benign,
}

/// Parse a pass-2 judgment from model content JSON.
pub fn parse_judgment(content: &str) -> Option<Judgment> {
    // Tolerant: find the first {...} JSON object in the content.
    let start = content.find('{')?;
    let end = content.rfind('}')? + 1;
    // The last '}' may precede the first '{' (e.g. a stray '}' and an unclosed
    // '{'); slicing content[start..end] would then panic, so bail out instead.
    if start >= end {
        return None;
    }
    let v: Value = serde_json::from_str(&content[start..end]).ok()?;
    let verdict = match v.get("verdict")?.as_str()? {
        "vuln" => Verdict::Vuln,
        "benign" => Verdict::Benign,
        _ => return None,
    };
    let p = v.get("p")?.as_f64()?;
    let note = v.get("note").and_then(|x| x.as_str()).unwrap_or("").to_string();
    Some(Judgment { verdict, p, note })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prefix_is_versioned_and_stable() {
        assert!(frozen_prefix("v3").contains("Rubric version: v3"));
        assert_eq!(frozen_prefix("v3"), frozen_prefix("v3"));
    }

    #[test]
    fn assembly_contains_all_parts() {
        let p = frozen_prefix("v3");
        let prompt = assemble_pass1(&p, "panic-on-input", "fn f(){ x.unwrap(); }");
        assert!(prompt.contains("belay"));
        assert!(prompt.contains("panic-on-input"));
        assert!(prompt.contains("x.unwrap()"));
    }

    #[test]
    fn parse_judgment_roundtrip() {
        let j = parse_judgment(r#"some text {"verdict":"vuln","p":0.93,"note":"ok"} trailing"#);
        let j = j.unwrap();
        assert_eq!(j.verdict, Verdict::Vuln);
        assert!((j.p - 0.93).abs() < 1e-9);
    }

    #[test]
    fn parse_judgment_brace_order_no_panic() {
        // Last '}' precedes first '{' (a stray '}' then an unclosed '{').
        // The old first-'{'/last-'}' heuristic panicked slicing [start..end];
        // this must return None instead of aborting the scan.
        assert!(parse_judgment(r#"} trailing {"verdict":"vuln""#).is_none());
    }
}
