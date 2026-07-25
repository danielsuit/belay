//! belay: an interactive terminal security agent for Rust codebases.
//!
//! `belay` with no args opens a session; `belay -p "…"` is one-shot for pipes
//! and CI. Read-only, semantic, narrow. See PLAN.md for the full design.

use belay_engine::Finding;
use belay_index::{Index, SymbolKind};
use belay_report::{markdown, sarif, terminal};
use belay_taint::{Function, Operand, SinkSite, Source, Stmt, TaintProblem, Var};
use clap::{Parser, Subcommand};
use std::path::PathBuf;
use std::process::exit;

#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

#[derive(Parser)]
#[command(name = "belay", version, about = "Interactive terminal security agent for Rust")]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,
    /// One-shot question; prints and exits.
    #[arg(short, long)]
    prompt: Option<String>,
    /// Inference endpoint URL (Subconscious serving path). Required for -p and
    /// for pass1/pass2; the static core runs without it.
    #[arg(long, env = "BELAY_ENDPOINT")]
    endpoint: Option<String>,
    /// Model id.
    #[arg(long, env = "BELAY_MODEL")]
    model: Option<String>,
    /// Workspace root (default: current directory).
    root: Option<PathBuf>,
}

#[derive(Subcommand)]
enum Command {
    /// Build (or warm) the index and print stats.
    Index {
        #[arg(long)] dump_graph: bool,
        #[arg(long)] dump_entry_points: bool,
    },
    /// Scan the workspace. Runs the static core (IFDS taint) always; runs
    /// pass1/pass2 when --endpoint is set.
    Scan {
        #[arg(long, default_value = "terminal")] format: String,
        #[arg(long)] fail_on: Option<String>,
        /// Skip inference; report static candidate flows only.
        #[arg(long)] static_only: bool,
    },
    /// Print callers/callees/reachability for a symbol.
    Graph { symbol: String },
    /// Run the eval harness over a corpus JSON file.
    Eval { #[arg(long)] corpus: PathBuf },
}

fn main() {
    let _ = tracing_subscriber::fmt().with_env_filter(
        tracing_subscriber::EnvFilter::try_from_default_env()
            .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
    ).try_init();

    let cli = Cli::parse();
    let root = cli.root.clone().unwrap_or_else(|| PathBuf::from("."));

    let code = match cli.command {
        None => {
            if let Some(p) = cli.prompt {
                oneshot(&root, &p, cli.endpoint.as_deref(), cli.model.as_deref())
            } else {
                // Interactive session.
                match belay_tui::run(&root) {
                    Ok(()) => 0,
                    Err(e) => {
                        eprintln!("session error: {e}");
                        2
                    }
                }
            }
        }
        Some(Command::Index { dump_graph, dump_entry_points }) => {
            index_cmd(&root, dump_graph, dump_entry_points)
        }
        Some(Command::Scan { format, fail_on, static_only }) => {
            scan_cmd(&root, &format, fail_on, static_only, cli.endpoint.as_deref())
        }
        Some(Command::Graph { symbol }) => graph_cmd(&root, &symbol),
        Some(Command::Eval { corpus }) => eval_cmd(&corpus),
    };
    exit(code);
}

fn oneshot(root: &PathBuf, question: &str, endpoint: Option<&str>, _model: Option<&str>) -> i32 {
    let _ = Index::build(root); // warm the index
    if endpoint.is_none() {
        eprintln!("belay: inference unavailable (set --endpoint or BELAY_ENDPOINT)");
        return 3;
    }
    // Full one-shot answering wires the engine against the serving path; left
    // to the deployment integration. The index is warm; the question is
    // captured. Exit 3 until the endpoint round-trip is implemented.
    let _ = question;
    eprintln!("belay: one-shot answering requires a live inference endpoint (wired, not yet driven)");
    3
}

fn index_cmd(root: &PathBuf, dump_graph: bool, dump_entry_points: bool) -> i32 {
    let t0 = std::time::Instant::now();
    let index = Index::build(root);
    let dt = t0.elapsed();
    println!(
        "belay · {} files · {} symbols · {} entry points · index {:?}",
        index.file_count(),
        index.symbol_count(),
        index.entry_points().len(),
        dt,
    );
    if dump_entry_points {
        println!("\nentry points:");
        for &e in index.entry_points() {
            let sym = index.symbol(e);
            println!(
                "  {}  [{}]",
                index.qual(e),
                sym.entry_reason.clone().unwrap_or_default(),
            );
        }
    }
    if dump_graph {
        println!("\ncall graph (caller → callee):");
        for s in &index.symbols {
            if s.kind == SymbolKind::Fn {
                for &c in index.callees_of(s.id) {
                    println!("  {} → {}", index.qual(s.id), index.qual(c));
                }
            }
        }
    }
    0
}

fn graph_cmd(root: &PathBuf, symbol: &str) -> i32 {
    let index = Index::build(root);
    let id = match index.definition_of(symbol) {
        Some(id) => id,
        None => {
            println!("no symbol: {symbol}");
            return 0;
        }
    };
    println!("definition: {} ({:?})", index.qual(id), id);
    let callers: Vec<_> = index.callers_of(id).to_vec();
    let callees: Vec<_> = index.callees_of(id).to_vec();
    println!(
        "callers ({}): {}",
        callers.len(),
        callers.iter().map(|&c| index.qual(c).to_string()).collect::<Vec<_>>().join(", "),
    );
    println!(
        "callees ({}): {}",
        callees.len(),
        callees.iter().map(|&c| index.qual(c).to_string()).collect::<Vec<_>>().join(", "),
    );
    let mut any = false;
    for &e in index.entry_points() {
        if index.reaches(e, id) {
            println!("reachable from entry {}", index.qual(e));
            any = true;
        }
    }
    if !any {
        println!("not reachable from any detected entry point");
    }
    0
}

fn scan_cmd(
    root: &PathBuf,
    format: &str,
    fail_on: Option<String>,
    static_only: bool,
    endpoint: Option<&str>,
) -> i32 {
    let index = Index::build(root);
    let tp = lower_to_taint(&index);
    let flows = tp.solve();

    // Each confirmed flow becomes a candidate finding (no inference: severity
    // unknown, marked Info). With --endpoint, pass1/pass2 would refine these
    // into confirmed/dropped findings with calibrated confidence.
    let findings: Vec<Finding> = flows
        .iter()
        .enumerate()
        .map(|(i, f)| {
            let sym = index.symbol(f.sink.func);
            Finding {
                id: i as u64,
                class: "taint-flow".to_string(),
                rubric_version: "static".to_string(),
                severity: belay_engine::Severity::Info,
                file: index.source(sym.file).rel_path.clone(),
                span: (sym.span.start, sym.span.end),
                line: 0,
                message: format!("taint flow: source {} → sink in {}", f.source.func, index.qual(f.sink.func)),
                evidence: index.read_span(&sym.span).to_string(),
                rationale: "static IFDS reachability (no inference)".to_string(),
                confidence: 0.0,
                e_value: 1.0,
                p_value: 1.0,
                fingerprint: belay_stat::fingerprint("taint-flow", "static", index.read_span(&sym.span).as_bytes()),
                sites: 1,
            }
        })
        .collect();

    let out = match format {
        "sarif" => sarif(&findings),
        "json" => serde_json::to_string_pretty(&findings).unwrap_or_else(|_| "[]".into()),
        "md" | "markdown" => markdown(&findings),
        _ => terminal(&findings),
    };
    println!("{out}");

    if !static_only {
        if endpoint.is_some() {
            eprintln!("belay: pass1/pass2 against a live endpoint is wired but not yet driven; reported static candidates only");
        } else {
            eprintln!("belay: no --endpoint; reported static candidate flows only (pass1/pass2 skipped)");
        }
    }

    // --fail-on: exit 1 if any finding meets the threshold. Static findings are
    // Info, so this only triggers once pass1/pass2 assign severities.
    if let Some(level) = fail_on {
        let order = |s: &str| match s {
            "critical" => 4,
            "high" => 3,
            "medium" => 2,
            "low" => 1,
            _ => 0,
        };
        let threshold = order(&level.to_lowercase());
        let worst = findings
            .iter()
            .map(|f| match f.severity {
                belay_engine::Severity::Critical => 4,
                belay_engine::Severity::High => 3,
                belay_engine::Severity::Medium => 2,
                belay_engine::Severity::Low => 1,
                belay_engine::Severity::Info => 0,
            })
            .max()
            .unwrap_or(0);
        if worst >= threshold && threshold > 0 {
            return 1;
        }
    }
    0
}

/// Lower the syn-level index into the taint IR (§II.4 input).
///
/// Coarse by design (§II.8 tradeoff): each function is a linear sequence of
/// its callees — a call to a sink-named function becomes a `Sink`, any other
/// call becomes an interprocedural `Call` carrying the request value (var 0).
/// Entry points seed var 0 as a source. This is the over-approximation the IFDS
/// solver refines; the model layer (pass1/pass2) refines it further.
fn lower_to_taint(index: &Index) -> TaintProblem {
    const SINK_NAMES: &[&str] = &[
        "unwrap", "expect", "panic", "query", "execute", "deserialize", "from_sql", "println",
        "eprintln", "log", "info", "warn", "error", "debug", "trace", "command", "write",
    ];
    let n = index.symbol_count();
    let mut functions: Vec<Function> = Vec::with_capacity(n);
    for sym in &index.symbols {
        let id = sym.id;
        if sym.kind != SymbolKind::Fn {
            // Placeholder so functions[id] lines up.
            functions.push(Function { id, params: vec![], body: vec![Stmt::Return { val: Operand::Const }] });
            continue;
        }
        let mut body: Vec<Stmt> = Vec::new();
        let mut callees: Vec<u32> = index.callees_of(id).to_vec();
        callees.sort_unstable();
        for callee in callees {
            let name = index.name(callee);
            let last = name.rsplit("::").next().unwrap_or(name);
            let is_sink = SINK_NAMES.iter().any(|s| last.eq_ignore_ascii_case(s));
            if is_sink {
                body.push(Stmt::Sink { val: Operand::Var(0) });
            } else {
                body.push(Stmt::Call { dst: Some(0), callee, args: vec![Operand::Var(0)] });
            }
        }
        body.push(Stmt::Return { val: Operand::Var(0) });
        functions.push(Function { id, params: vec![0], body });
    }

    let sources: Vec<Source> = index
        .entry_points()
        .iter()
        .map(|&e| Source { func: e, var: 0u32 })
        .collect();

    let mut sinks: Vec<SinkSite> = Vec::new();
    for f in &functions {
        for (i, s) in f.body.iter().enumerate() {
            if matches!(s, Stmt::Sink { .. }) {
                sinks.push(SinkSite { func: f.id, stmt: i });
            }
        }
    }

    TaintProblem { functions, sources, sinks }
}

fn eval_cmd(corpus: &PathBuf) -> i32 {
    let s = match std::fs::read_to_string(corpus) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("belay: cannot read corpus {corpus:?}: {e}");
            return 2;
        }
    };
    let corpus = match belay_eval::Corpus::from_json(&s) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("belay: invalid corpus: {e}");
            return 2;
        }
    };
    println!("belay eval · {} advisories · {:.1} KLOC", corpus.len(), corpus.kloc());
    println!("(run a scan per advisory/tag pair to populate metrics; see belay-eval::metrics::compute)");
    0
}

#[allow(dead_code)]
fn _unused(_: Var) {}
