// belay-cli: clap, session, wiring → binary `belay`.
// Scaffold: real CLI parsed in M8/M10; stubbed now so the workspace builds.
use clap::Parser;

#[derive(Parser, Debug)]
#[command(name = "belay", version, about = "Interactive terminal security agent for Rust")]
pub struct Cli {
    /// One-shot prompt; prints answer and exits (pipes/CI).
    #[arg(short = 'p', long)]
    pub prompt: Option<String>,

    #[command(subcommand)]
    pub command: Option<Command>,
}

#[derive(clap::Subcommand, Debug)]
pub enum Command {
    /// Build/inspect the index.
    Index {
        #[arg(long)] dump_graph: bool,
        #[arg(long)] dump_entry_points: bool,
    },
    /// Run a scan.
    Scan {
        #[arg(long, default_value = "json")] format: String,
        #[arg(long)] fail_on: Option<String>,
    },
    /// Evaluate against a corpus.
    Eval {
        #[arg(long)] corpus: String,
    },
}

pub fn run(cli: Cli) -> std::process::ExitCode {
    eprintln!("belay: workspace built. cli={:?}", cli.command.as_ref().map(|c| format!("{c:?}")).unwrap_or_else(|| "session".into()));
    std::process::ExitCode::SUCCESS
}
