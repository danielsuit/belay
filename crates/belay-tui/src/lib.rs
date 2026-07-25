//! belay-tui: the interactive session (§M8, §V).
//!
//! A minimal but real terminal session: a header with index stats, a
//! scrollable output pane, and an input line. Slash commands that need only the
//! index (`/entrypoints`, `/graph`, `/cost`, `/quit`) work offline; bare
//! questions require an inference endpoint and are forwarded by the engine in
//! a full deployment. The render loop reads an `Arc<Index>` and never blocks on
//! I/O (§V.2).

use belay_index::Index;
use ratatui::{
    layout::{Constraint, Direction, Layout},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem, Paragraph},
    Terminal,
};
use std::io::{self, stdout};
use std::path::Path;

pub fn run(root: &Path) -> io::Result<()> {
    let index = Index::build(root);
    let mut app = App::new(index, root);
    app.log(format!(
        "belay · {} files · {} symbols · {} entry points",
        app.index.file_count(),
        app.index.symbol_count(),
        app.index.entry_points().len(),
    ));
    app.log("type /entrypoints, /graph <sym>, /cost, /quit  —  bare questions need an inference endpoint".into());

    crossterm::terminal::enable_raw_mode()?;
    let mut stdout = stdout();
    crossterm::execute!(stdout, crossterm::terminal::EnterAlternateScreen)?;
    let backend = ratatui::backend::CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    loop {
        terminal.draw(|f| app.render(f))?;
        if crossterm::event::poll(std::time::Duration::from_millis(100))? {
            if let crossterm::event::Event::Key(k) = crossterm::event::read()? {
                use crossterm::event::{KeyCode, KeyEvent};
                let KeyEvent { code, .. } = k;
                match code {
                    KeyCode::Enter => {
                        let line = std::mem::take(&mut app.input);
                        if app.handle_command(&line) {
                            break;
                        }
                    }
                    KeyCode::Char(c) => app.input.push(c),
                    KeyCode::Backspace => {
                        app.input.pop();
                    }
                    KeyCode::Esc => break,
                    _ => {}
                }
            }
        }
    }

    disable_raw()?;
    Ok(())
}

fn disable_raw() -> io::Result<()> {
    crossterm::execute!(stdout(), crossterm::terminal::LeaveAlternateScreen)?;
    crossterm::terminal::disable_raw_mode()?;
    Ok(())
}

struct App {
    index: Index,
    root: String,
    input: String,
    lines: Vec<String>,
    scroll: usize,
}

impl App {
    fn new(index: Index, root: &Path) -> Self {
        Self {
            index,
            root: root.display().to_string(),
            input: String::new(),
            lines: Vec::new(),
        
            scroll: 0,
        }
    }

    fn log(&mut self, s: String) {
        self.lines.push(s);
        self.scroll = self.lines.len().saturating_sub(1);
    }

    fn handle_command(&mut self, line: &str) -> bool {
        let line = line.trim();
        if line.is_empty() {
            return false;
        }
        let out = self.compute_reply(line);
        for l in out {
            self.log(l);
        }
        false
    }

    /// Build reply lines without mutating self (avoids the double-borrow of
    /// `self.log(format!(… self.index …))`).
    fn compute_reply(&self, line: &str) -> Vec<String> {
        if let Some(rest) = line.strip_prefix('/') {
            let mut parts = rest.split_whitespace();
            let cmd = parts.next().unwrap_or("");
            match cmd {
                "quit" | "q" | "exit" => {
                    std::process::exit(0);
                }
                "entrypoints" => {
                    let mut out = Vec::new();
                    for &e in self.index.entry_points() {
                        let sym = self.index.symbol(e);
                        let reason = sym.entry_reason.clone().unwrap_or_default();
                        out.push(format!("  {}  [{}]", self.index.qual(e), reason));
                    }
                    out
                }
                "graph" => {
                    let sym_name = parts.next().unwrap_or("");
                    let mut out = Vec::new();
                    match self.index.definition_of(sym_name) {
                        Some(id) => {
                            out.push(format!("definition: {} ({:?})", self.index.qual(id), id));
                            let callers: Vec<_> = self.index.callers_of(id).to_vec();
                            let callees: Vec<_> = self.index.callees_of(id).to_vec();
                            let cq: Vec<String> =
                                callers.iter().map(|&c| self.index.qual(c).to_string()).collect();
                            let ceq: Vec<String> =
                                callees.iter().map(|&c| self.index.qual(c).to_string()).collect();
                            out.push(format!("callers ({}): {}", callers.len(), cq.join(", ")));
                            out.push(format!("callees ({}): {}", callees.len(), ceq.join(", ")));
                            for &e in self.index.entry_points() {
                                if self.index.reaches(e, id) {
                                    out.push(format!("reachable from entry {}", self.index.qual(e)));
                                }
                            }
                        }
                        None => out.push(format!("no symbol: {sym_name}")),
                    }
                    out
                }
                "cost" => vec!["no scan this session (tokens $0.00)".into()],
                _ => vec![format!("unknown command: /{cmd}")],
            }
        } else {
            vec![
                format!("› {line}"),
                "  (answering questions needs an inference endpoint; pass --endpoint)".into(),
            ]
        }
    }

    fn render(&mut self, f: &mut ratatui::Frame) {
        let area = f.area();
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Length(3), Constraint::Min(1), Constraint::Length(3)])
            .split(area);

        // Header.
        let header = Paragraph::new(vec![Line::from(vec![
            Span::styled(
                format!(" belay · {} ", self.root),
                Style::default().add_modifier(Modifier::BOLD).fg(Color::Cyan),
            ),
            Span::raw(format!(
                "· {} files · {} symbols · {} entry points",
                self.index.file_count(),
                self.index.symbol_count(),
                self.index.entry_points().len(),
            )),
        ])])
        .block(Block::default().borders(Borders::ALL).title("session"));
        f.render_widget(header, chunks[0]);

        // Body: scrollable lines.
        let visible_height = chunks[1].height as usize;
        let total = self.lines.len();
        let start = self.scroll.saturating_sub(visible_height.saturating_sub(1)).min(total);
        let shown: Vec<ListItem> = self
            .lines
            .iter()
            .skip(start)
            .take(visible_height)
            .map(|s| ListItem::new(s.clone()))
            .collect();
        let list = List::new(shown).block(Block::default().borders(Borders::ALL).title("output"));
        f.render_widget(list, chunks[1]);

        // Input.
        let input = Paragraph::new(format!("› {}", self.input))
            .block(Block::default().borders(Borders::ALL).title("input"));
        f.render_widget(input, chunks[2]);
        f.set_cursor_position((3 + self.input.len() as u16, chunks[2].y + 1));
    }
}
