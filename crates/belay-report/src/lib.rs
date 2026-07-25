//! belay-report: SARIF 2.1.0, markdown, and terminal rendering of findings.
//!
//! SARIF is the lingua franca of CI (GitHub code-scanning ingests it directly).
//! Markdown is for humans in a PR. Terminal is for the session inbox.

use belay_engine::Finding;
use serde::Serialize;
use serde_json::{json, Value};

/// Render findings as a SARIF 2.1.0 log (validates against the SARIF schema
/// and renders in the GitHub code-scanning UI).
pub fn sarif(findings: &[Finding]) -> String {
    let results: Vec<Value> = findings.iter().map(finding_to_sarif_result).collect();
    let mut rules: Vec<Value> = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for f in findings {
        if seen.insert(&f.class) {
            rules.push(json!({
                "id": f.class,
                "name": f.class,
                "shortDescription": { "text": f.class },
                "defaultConfiguration": { "level": f.severity.sarif_level() },
            }));
        }
    }
    let run = json!({
        "tool": {
            "driver": {
                "name": "belay",
                "informationUri": "https://github.com/danielsuit/belay",
                "rules": rules,
            }
        },
        "results": results,
    });
    let log = json!({
        "version": "2.1.0",
        "$schema": "https://docs.oasis-open.org/sarif/sarif/v2.1.0/cs01/schemas/sarif-schema-2.1.0.json",
        "runs": [run],
    });
    serde_json::to_string_pretty(&log).unwrap_or_else(|_| "{}".to_string())
}

fn finding_to_sarif_result(f: &Finding) -> Value {
    json!({
        "ruleId": f.class,
        "level": f.severity.sarif_level(),
        "message": { "text": f.message },
        "locations": [{
            "physicalLocation": {
                "artifactLocation": { "uri": f.file },
                "region": {
                    "startLine": f.line,
                    "byteOffset": f.span.0,
                    "byteLength": f.span.1.saturating_sub(f.span.0),
                }
            }
        }],
        "partialFingerprints": {
            "belay/primary": hex(&f.fingerprint)
        },
        "properties": {
            "confidence": f.confidence,
            "eValue": f.e_value,
            "pValue": f.p_value,
            "sites": f.sites,
            "rationale": f.rationale,
            "rubricVersion": f.rubric_version,
        }
    })
}

/// Markdown report for a PR comment.
pub fn markdown(findings: &[Finding]) -> String {
    let mut s = String::new();
    s.push_str("# belay scan\n\n");
    if findings.is_empty() {
        s.push_str("_No findings at the configured FDR threshold._\n");
        return s;
    }
    s.push_str(&format!("{} finding(s)\n\n", findings.len()));
    s.push_str("| Severity | Class | File:Line | Confidence | Sites | Message |\n");
    s.push_str("|---|---|---|---|---|---|\n");
    for f in findings {
        s.push_str(&format!(
            "| {} | `{}` | `{}:{}` | {:.2} | {} | {} |\n",
            f.severity.as_str(),
            f.class,
            f.file,
            f.line,
            f.confidence,
            f.sites,
            f.message.replace('|', "\\|"),
        ));
    }
    s
}

/// Terminal rendering (ANSI-light; the TUI does the fancy version).
pub fn terminal(findings: &[Finding]) -> String {
    let mut s = String::new();
    if findings.is_empty() {
        s.push_str("no findings\n");
        return s;
    }
    for f in findings {
        s.push_str(&format!(
            "{:<8} {:<22} {}:{}  p={:.2} e={:.1}\n  {}\n  > {}\n\n",
            f.severity.as_str(),
            f.class,
            f.file,
            f.line,
            f.confidence,
            f.e_value,
            f.message,
            f.evidence.lines().next().unwrap_or("").trim(),
        ));
    }
    s
}

/// A summary header string (findings count by severity) for the session banner.
#[derive(Clone, Debug, Serialize)]
pub struct Summary {
    pub total: usize,
    pub critical: usize,
    pub high: usize,
    pub medium: usize,
    pub low: usize,
    pub info: usize,
}

pub fn summary(findings: &[Finding]) -> Summary {
    let mut s = Summary { total: findings.len(), critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    for f in findings {
        match f.severity {
            belay_engine::Severity::Critical => s.critical += 1,
            belay_engine::Severity::High => s.high += 1,
            belay_engine::Severity::Medium => s.medium += 1,
            belay_engine::Severity::Low => s.low += 1,
            belay_engine::Severity::Info => s.info += 1,
        }
    }
    s
}

fn hex(bytes: &[u8; 16]) -> String {
    let mut s = String::with_capacity(32);
    for b in bytes {
        s.push_str(&format!("{:02x}", b));
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use belay_engine::Severity;

    fn sample() -> Finding {
        Finding {
            id: 1,
            class: "tenant-isolation".into(),
            rubric_version: "v3".into(),
            severity: Severity::High,
            file: "src/cache.rs".into(),
            span: (10, 20),
            line: 42,
            message: "cache key not tenant-scoped".into(),
            evidence: "fn get(key: &str)".into(),
            rationale: "no tenant prefix".into(),
            confidence: 0.9,
            e_value: 12.0,
            p_value: 0.02,
            fingerprint: [0xab; 16],
            sites: 3,
        }
    }

    #[test]
    fn sarif_is_valid_json_with_version() {
        let s = sarif(&[sample()]);
        let v: Value = serde_json::from_str(&s).unwrap();
        assert_eq!(v["version"], "2.1.0");
        assert_eq!(v["runs"][0]["tool"]["driver"]["name"], "belay");
        assert_eq!(v["runs"][0]["results"][0]["ruleId"], "tenant-isolation");
        assert_eq!(v["runs"][0]["results"][0]["level"], "error");
    }

    #[test]
    fn markdown_has_table_and_findings() {
        let m = markdown(&[sample()]);
        assert!(m.contains("tenant-isolation"));
        assert!(m.contains("src/cache.rs:42"));
    }

    #[test]
    fn terminal_shows_severity_and_line() {
        let t = terminal(&[sample()]);
        assert!(t.contains("high"));
        assert!(t.contains("src/cache.rs:42"));
    }

    #[test]
    fn summary_counts_severities() {
        let s = summary(&[sample()]);
        assert_eq!(s.high, 1);
        assert_eq!(s.total, 1);
    }
}
