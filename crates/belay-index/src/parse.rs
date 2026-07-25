//! Walk + parse: `ignore` walk → `rayon` `syn::parse_file` → per-file partial
//! index → merge.
//!
//! Module paths are approximated from the file's relative path (the `syn`-level
//! tradeoff from §II.8 — no crate name resolution). Call edges are recorded as
//! rendered callee paths and resolved to [`SymbolId`]s at merge time by name;
//! ambiguous names are left unresolved (no edge) rather than guessed wrong.

use crate::entry;
use crate::ids::{SpurKey, SymbolId};
use crate::interner::Interner;
use crate::source::{load_file, SourceFile};
use crate::span::LineCol;
use crate::symbol::{Symbol, SymbolKind};
use rayon::prelude::*;
use std::path::{Path, PathBuf};
use std::sync::Arc;

/// A symbol before it has a global [`SymbolId`] / file id.
#[derive(Clone, Debug)]
struct ProtoSymbol {
    name: String,
    qual: String,
    kind: SymbolKind,
    span_start: LineCol,
    span_end: LineCol,
    name_start: LineCol,
    name_end: LineCol,
    entry_reason: Option<String>,
}

/// A call edge before callee resolution: caller is a *local* index into the
/// file's symbol vector; callee is a rendered path string.
#[derive(Clone, Debug)]
struct ProtoCall {
    caller_local: u32,
    callee: String,
}

pub(crate) struct FileParse {
    rel_path: String,
    abs_path: PathBuf,
    symbols: Vec<ProtoSymbol>,
    calls: Vec<ProtoCall>,
}

fn walk_and_parse(root: &Path) -> Vec<FileParse> {
    let paths: Vec<(PathBuf, String)> = ignore::WalkBuilder::new(root)
        .hidden(true)
        .git_ignore(true)
        .git_exclude(true)
        .parents(true)
        .build()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().map(|t| t.is_file()).unwrap_or(false))
        .filter(|e| {
            e.path()
                .extension()
                .map(|x| x == std::ffi::OsStr::new("rs"))
                .unwrap_or(false)
        })
        .map(|e| {
            let abs = e.path().to_path_buf();
            let rel = e
                .path()
                .strip_prefix(root)
                .map(|p| p.to_string_lossy().replace('\\', "/"))
                .unwrap_or_else(|_| e.path().to_string_lossy().into_owned());
            (abs, rel)
        })
        .collect();

    paths
        .par_iter()
        .map(|(abs, rel)| parse_file(abs, rel).unwrap_or(FileParse {
            rel_path: rel.clone(),
            abs_path: abs.clone(),
            symbols: Vec::new(),
            calls: Vec::new(),
        }))
        .collect()
}

fn parse_file(abs: &Path, rel: &str) -> Option<FileParse> {
    let bytes: Arc<[u8]> = Arc::from(std::fs::read(abs).ok()?.into_boxed_slice());
    if std::str::from_utf8(&bytes).is_err() {
        return None;
    }
    let src = std::str::from_utf8(&bytes).ok()?;
    let file = syn::parse_file(src).ok()?;
    let mut symbols = Vec::new();
    let mut calls = Vec::new();

    let root_mod = root_module_of(rel);
    let mut ctx = WalkCtx { mod_path: vec![root_mod] };
    walk_items(&file.items, &mut ctx, &mut symbols, &mut calls);

    Some(FileParse {
        rel_path: rel.to_string(),
        abs_path: abs.to_path_buf(),
        symbols,
        calls,
    })
}

struct WalkCtx {
    mod_path: Vec<String>,
}

fn root_module_of(rel: &str) -> String {
    let p = rel.strip_suffix(".rs").unwrap_or(rel);
    let p = p.strip_prefix("src/").unwrap_or(p);
    let p = p.replace('/', "::");
    match p.rsplit("::").next().unwrap_or("") {
        "mod" | "lib" | "main" => {
            let idx = p.rfind("::").unwrap_or(0);
            p[..idx].to_string()
        }
        _ => p,
    }
}

fn walk_items(
    items: &[syn::Item],
    ctx: &mut WalkCtx,
    symbols: &mut Vec<ProtoSymbol>,
    calls: &mut Vec<ProtoCall>,
) {
    for item in items {
        match item {
            syn::Item::Fn(f) => {
                let local = symbols.len() as u32;
                let Some(proto) = mk_fn_symbol(f, ctx) else {
                    continue;
                };
                symbols.push(proto);
                collect_block_calls(&f.block, local, calls);
            }
            syn::Item::Mod(m) => {
                let (span_start, span_end) = match &m.content {
                    Some((brace, _)) => (lc(m.mod_token.span.start()), lc(brace.span.close().end())),
                    None => (lc(m.mod_token.span.start()), lc(m.mod_token.span.end())),
                };
                symbols.push(ProtoSymbol {
                    name: m.ident.to_string(),
                    qual: qual_of(ctx, &m.ident.to_string()),
                    kind: SymbolKind::Mod,
                    span_start,
                    span_end,
                    name_start: lc(m.ident.span().start()),
                    name_end: lc(m.ident.span().end()),
                    entry_reason: None,
                });
                if let Some((_, inline)) = &m.content {
                    ctx.mod_path.push(m.ident.to_string());
                    walk_items(inline, ctx, symbols, calls);
                    ctx.mod_path.pop();
                }
            }
            syn::Item::Struct(s) => {
                let end = field_end_or_ident(&s.fields, s.ident.span());
                symbols.push(ProtoSymbol {
                    name: s.ident.to_string(),
                    qual: qual_of(ctx, &s.ident.to_string()),
                    kind: SymbolKind::Struct,
                    span_start: lc(s.struct_token.span.start()),
                    span_end: end,
                    name_start: lc(s.ident.span().start()),
                    name_end: lc(s.ident.span().end()),
                    entry_reason: None,
                });
                for f in &s.fields {
                    if let Some(ident) = &f.ident {
                        symbols.push(ProtoSymbol {
                            name: ident.to_string(),
                            qual: qual_of(ctx, &ident.to_string()),
                            kind: SymbolKind::Field,
                            span_start: lc(ident.span().start()),
                            span_end: lc(ident.span().end()),
                            name_start: lc(ident.span().start()),
                            name_end: lc(ident.span().end()),
                            entry_reason: None,
                        });
                    }
                }
            }
            syn::Item::Enum(e) => {
                symbols.push(ProtoSymbol {
                    name: e.ident.to_string(),
                    qual: qual_of(ctx, &e.ident.to_string()),
                    kind: SymbolKind::Enum,
                    span_start: lc(e.enum_token.span.start()),
                    span_end: lc(e.brace_token.span.close().end()),
                    name_start: lc(e.ident.span().start()),
                    name_end: lc(e.ident.span().end()),
                    entry_reason: None,
                });
                for v in &e.variants {
                    let end = field_end_or_ident(&v.fields, v.ident.span());
                    symbols.push(ProtoSymbol {
                        name: v.ident.to_string(),
                        qual: qual_of(ctx, &v.ident.to_string()),
                        kind: SymbolKind::Variant,
                        span_start: lc(v.ident.span().start()),
                        span_end: end,
                        name_start: lc(v.ident.span().start()),
                        name_end: lc(v.ident.span().end()),
                        entry_reason: None,
                    });
                }
            }
            syn::Item::Trait(t) => {
                symbols.push(ProtoSymbol {
                    name: t.ident.to_string(),
                    qual: qual_of(ctx, &t.ident.to_string()),
                    kind: SymbolKind::Trait,
                    span_start: lc(t.trait_token.span.start()),
                    span_end: lc(t.brace_token.span.close().end()),
                    name_start: lc(t.ident.span().start()),
                    name_end: lc(t.ident.span().end()),
                    entry_reason: None,
                });
                for ti in &t.items {
                    if let syn::TraitItem::Fn(tf) = ti {
                        let local = symbols.len() as u32;
                        let end = match &tf.default {
                            Some(b) => lc(b.brace_token.span.close().end()),
                            None => lc(tf.sig.fn_token.span.end()),
                        };
                        let name = tf.sig.ident.to_string();
                        let attrs: Vec<String> =
                            tf.attrs.iter().map(|a| path_to_string(a.path())).collect();
                        let param_types: Vec<String> = tf
                            .sig
                            .inputs
                            .iter()
                            .filter_map(|arg| match arg {
                                syn::FnArg::Typed(p) => Some(type_to_string(p.ty.as_ref())),
                                syn::FnArg::Receiver(_) => None,
                            })
                            .collect();
                        let entry_reason = entry::classify_fn_entry(&name, &attrs, &param_types);
                        symbols.push(ProtoSymbol {
                            name: name.clone(),
                            qual: qual_of(ctx, &name),
                            kind: SymbolKind::Fn,
                            span_start: lc(tf.sig.fn_token.span.start()),
                            span_end: end,
                            name_start: lc(tf.sig.ident.span().start()),
                            name_end: lc(tf.sig.ident.span().end()),
                            entry_reason,
                        });
                        if let Some(b) = &tf.default {
                            collect_block_calls(b, local, calls);
                        }
                    }
                }
            }
            syn::Item::Impl(i) => {
                let self_ty = type_to_string(i.self_ty.as_ref());
                symbols.push(ProtoSymbol {
                    name: self_ty.clone(),
                    qual: qual_of(ctx, &format!("<impl {self_ty}>")),
                    kind: SymbolKind::Impl,
                    span_start: lc(i.impl_token.span.start()),
                    span_end: lc(i.brace_token.span.close().end()),
                    name_start: lc(i.impl_token.span.start()),
                    name_end: lc(i.impl_token.span.end()),
                    entry_reason: None,
                });
                for ii in &i.items {
                    if let syn::ImplItem::Fn(f) = ii {
                        let local = symbols.len() as u32;
                        let name = f.sig.ident.to_string();
                        let attrs: Vec<String> =
                            f.attrs.iter().map(|a| path_to_string(a.path())).collect();
                        let param_types: Vec<String> = f
                            .sig
                            .inputs
                            .iter()
                            .filter_map(|arg| match arg {
                                syn::FnArg::Typed(p) => Some(type_to_string(p.ty.as_ref())),
                                syn::FnArg::Receiver(_) => Some(format!("self:{self_ty}")),
                            })
                            .collect();
                        let entry_reason = entry::classify_fn_entry(&name, &attrs, &param_types);
                        symbols.push(ProtoSymbol {
                            name: name.clone(),
                            qual: qual_of(ctx, &name),
                            kind: SymbolKind::Fn,
                            span_start: lc(f.sig.fn_token.span.start()),
                            span_end: lc(f.block.brace_token.span.close().end()),
                            name_start: lc(f.sig.ident.span().start()),
                            name_end: lc(f.sig.ident.span().end()),
                            entry_reason,
                        });
                        collect_block_calls(&f.block, local, calls);
                    }
                }
            }
            syn::Item::Const(c) => symbols.push(named_simple(ctx, &c.ident, SymbolKind::Const, c.const_token.span.start(), c.ident.span())),
            syn::Item::Static(s) => symbols.push(named_simple(ctx, &s.ident, SymbolKind::Static, s.static_token.span.start(), s.ident.span())),
            syn::Item::Type(t) => symbols.push(named_simple(ctx, &t.ident, SymbolKind::TypeAlias, t.type_token.span.start(), t.ident.span())),
            syn::Item::Macro(_) => {}
            _ => {}
        }
    }
}

fn named_simple(
    ctx: &WalkCtx,
    ident: &proc_macro2::Ident,
    kind: SymbolKind,
    kw_start: proc_macro2::LineColumn,
    ident_span: proc_macro2::Span,
) -> ProtoSymbol {
    let name = ident.to_string();
    ProtoSymbol {
        name: name.clone(),
        qual: qual_of(ctx, &name),
        kind,
        span_start: lc(kw_start),
        span_end: lc(ident_span.end()),
        name_start: lc(ident_span.start()),
        name_end: lc(ident_span.end()),
        entry_reason: None,
    }
}

fn mk_fn_symbol(f: &syn::ItemFn, ctx: &WalkCtx) -> Option<ProtoSymbol> {
    let name = f.sig.ident.to_string();
    let attrs: Vec<String> = f.attrs.iter().map(|a| path_to_string(a.path())).collect();
    let param_types: Vec<String> = f
        .sig
        .inputs
        .iter()
        .filter_map(|arg| match arg {
            syn::FnArg::Typed(p) => Some(type_to_string(p.ty.as_ref())),
            syn::FnArg::Receiver(_) => None,
        })
        .collect();
    let entry_reason = entry::classify_fn_entry(&name, &attrs, &param_types);
    Some(ProtoSymbol {
        name: name.clone(),
        qual: qual_of(ctx, &name),
        kind: SymbolKind::Fn,
        span_start: lc(f.sig.fn_token.span.start()),
        span_end: lc(f.block.brace_token.span.close().end()),
        name_start: lc(f.sig.ident.span().start()),
        name_end: lc(f.sig.ident.span().end()),
        entry_reason,
    })
}

/// End of a `Fields` list (the closing brace/paren), falling back to the
/// ident span for unit variants.
fn field_end_or_ident(fields: &syn::Fields, ident_span: proc_macro2::Span) -> LineCol {
    match fields {
        syn::Fields::Named(n) => lc(n.brace_token.span.close().end()),
        syn::Fields::Unnamed(u) => lc(u.paren_token.span.close().end()),
        syn::Fields::Unit => lc(ident_span.end()),
    }
}

fn collect_block_calls(block: &syn::Block, caller_local: u32, calls: &mut Vec<ProtoCall>) {
    let mut collector = CallCollector { out: Vec::new() };
    collector.visit_block(block);
    for c in collector.out.drain(..) {
        calls.push(ProtoCall { caller_local, callee: c });
    }
}

fn qual_of(ctx: &WalkCtx, name: &str) -> String {
    let mut s = String::new();
    for (i, m) in ctx.mod_path.iter().enumerate() {
        if !m.is_empty() {
            if i > 0 {
                s.push_str("::");
            }
            s.push_str(m);
        }
    }
    if !s.is_empty() {
        s.push_str("::");
    }
    s.push_str(name);
    s
}

fn lc(lc: proc_macro2::LineColumn) -> LineCol {
    LineCol::new(lc.line, lc.column)
}

fn path_to_string(p: &syn::Path) -> String {
    p.segments
        .iter()
        .map(|s| s.ident.to_string())
        .collect::<Vec<_>>()
        .join("::")
}

fn type_to_string(t: &syn::Type) -> String {
    match t {
        syn::Type::Path(tp) => {
            // Render with generic args so `Path<Id>` and `State<AppState>` match.
            let mut s = String::new();
            for (i, seg) in tp.path.segments.iter().enumerate() {
                if i > 0 {
                    s.push_str("::");
                }
                s.push_str(&seg.ident.to_string());
                if let syn::PathArguments::AngleBracketed(ab) = &seg.arguments {
                    let args: Vec<String> = ab
                        .args
                        .iter()
                        .filter_map(|a| match a {
                            syn::GenericArgument::Type(ty) => Some(type_to_string(ty)),
                            syn::GenericArgument::AssocType(at) => Some(at.ident.to_string()),
                            _ => None,
                        })
                        .collect();
                    if !args.is_empty() {
                        s.push('<');
                        s.push_str(&args.join(", "));
                        s.push('>');
                    }
                }
            }
            s
        }
        syn::Type::Reference(r) => {
            let inner = type_to_string(r.elem.as_ref());
            format!("&{inner}")
        }
        syn::Type::Tuple(tp) => {
            let elems: Vec<_> = tp.elems.iter().map(type_to_string).collect();
            format!("({})", elems.join(", "))
        }
        syn::Type::Array(a) => format!("[{}]", type_to_string(a.elem.as_ref())),
        syn::Type::Slice(s) => format!("[{}]", type_to_string(s.elem.as_ref())),
        syn::Type::Ptr(p) => format!("*{}", type_to_string(p.elem.as_ref())),
        syn::Type::Group(g) => type_to_string(&g.elem),
        syn::Type::Paren(p) => type_to_string(&p.elem),
        _ => "_".to_string(),
    }
}

struct CallCollector {
    out: Vec<String>,
}

impl CallCollector {
    fn visit_block(&mut self, block: &syn::Block) {
        for stmt in &block.stmts {
            self.visit_stmt(stmt);
        }
    }

    fn visit_stmt(&mut self, stmt: &syn::Stmt) {
        match stmt {
            syn::Stmt::Local(l) => {
                if let Some(init) = &l.init {
                    self.visit_expr(&init.expr);
                    if let Some((_, e)) = &init.diverge {
                        self.visit_expr(e);
                    }
                }
            }
            syn::Stmt::Expr(e, _) => self.visit_expr(e),
            syn::Stmt::Macro(_) | syn::Stmt::Item(_) => {}
        }
    }

    fn visit_expr(&mut self, e: &syn::Expr) {
        match e {
            syn::Expr::Call(c) => {
                self.out.push(callee_of(&c.func));
                for arg in &c.args {
                    self.visit_expr(arg);
                }
            }
            syn::Expr::MethodCall(m) => {
                self.out.push(m.method.to_string());
                self.visit_expr(&m.receiver);
                for arg in &m.args {
                    self.visit_expr(arg);
                }
            }
            syn::Expr::Closure(c) => self.visit_expr(&c.body),
            syn::Expr::Block(b) => {
                for s in &b.block.stmts {
                    self.visit_stmt(s);
                }
            }
            syn::Expr::If(i) => {
                self.visit_expr(&i.cond);
                for s in &i.then_branch.stmts {
                    self.visit_stmt(s);
                }
                if let Some((_, e)) = &i.else_branch {
                    self.visit_expr(e);
                }
            }
            syn::Expr::Match(m) => {
                self.visit_expr(&m.expr);
                for arm in &m.arms {
                    if let Some((_, g)) = &arm.guard {
                        self.visit_expr(g);
                    }
                    self.visit_expr(&arm.body);
                }
            }
            syn::Expr::Loop(l) => {
                for s in &l.body.stmts {
                    self.visit_stmt(s);
                }
            }
            syn::Expr::While(w) => {
                self.visit_expr(&w.cond);
                for s in &w.body.stmts {
                    self.visit_stmt(s);
                }
            }
            syn::Expr::ForLoop(f) => {
                self.visit_expr(&f.expr);
                for s in &f.body.stmts {
                    self.visit_stmt(s);
                }
            }
            syn::Expr::Binary(b) => {
                self.visit_expr(&b.left);
                self.visit_expr(&b.right);
            }
            syn::Expr::Assign(a) => {
                self.visit_expr(&a.left);
                self.visit_expr(&a.right);
            }
            syn::Expr::Let(l) => self.visit_expr(&l.expr),
            syn::Expr::Tuple(t) => {
                for e in &t.elems {
                    self.visit_expr(e);
                }
            }
            syn::Expr::Array(a) => {
                for e in &a.elems {
                    self.visit_expr(e);
                }
            }
            syn::Expr::Paren(p) => self.visit_expr(&p.expr),
            syn::Expr::Group(g) => self.visit_expr(&g.expr),
            syn::Expr::Field(f) => self.visit_expr(&f.base),
            syn::Expr::Index(i) => {
                self.visit_expr(&i.expr);
                self.visit_expr(&i.index);
            }
            syn::Expr::Reference(r) => self.visit_expr(&r.expr),
            syn::Expr::Unary(u) => self.visit_expr(&u.expr),
            syn::Expr::Await(a) => self.visit_expr(&a.base),
            syn::Expr::Try(t) => self.visit_expr(&t.expr),
            syn::Expr::Return(r) => {
                if let Some(e) = &r.expr {
                    self.visit_expr(e);
                }
            }
            syn::Expr::Path(_) | syn::Expr::Lit(_) | syn::Expr::Continue(_) => {}
            _ => {}
        }
    }
}

fn callee_of(func: &syn::Expr) -> String {
    match func {
        syn::Expr::Path(p) => path_to_string(&p.path),
        _ => "_".to_string(),
    }
}

pub(crate) struct Merged {
    pub sources: Vec<SourceFile>,
    pub symbols: Vec<Symbol>,
    pub edges: Vec<(SymbolId, SymbolId)>,
}

pub(crate) fn merge(file_parses: Vec<FileParse>, interner: &Interner) -> Merged {
    let mut sources: Vec<SourceFile> = Vec::with_capacity(file_parses.len());
    let mut symbols: Vec<Symbol> = Vec::new();
    let mut file_sym_base: Vec<u32> = Vec::with_capacity(file_parses.len());

    for (fid, fp) in file_parses.iter().enumerate() {
        let file_id = fid as crate::ids::FileId;
        let base = symbols.len() as u32;
        file_sym_base.push(base);
        let Some(src) = load_file(file_id, &fp.abs_path, &fp.rel_path) else {
            continue;
        };
        for ps in &fp.symbols {
            let span = src.span_of(file_id, ps.span_start, ps.span_end);
            let name_span = src.span_of(file_id, ps.name_start, ps.name_end);
            let id = symbols.len() as SymbolId;
            let name = interner.get_or_intern(&ps.name);
            let qual = interner.get_or_intern(&ps.qual);
            symbols.push(Symbol {
                id,
                name,
                qual,
                kind: ps.kind,
                file: file_id,
                span,
                name_span,
                entry: ps.entry_reason.is_some(),
                entry_reason: ps.entry_reason.clone(),
            });
        }
        sources.push(src);
    }

    let mut by_name: rustc_hash::FxHashMap<SpurKey, Vec<SymbolId>> =
        rustc_hash::FxHashMap::default();
    for s in &symbols {
        by_name.entry(s.name).or_default().push(s.id);
    }
    let mut by_qual: rustc_hash::FxHashMap<SpurKey, SymbolId> = rustc_hash::FxHashMap::default();
    for s in &symbols {
        by_qual.insert(s.qual, s.id);
    }

    let mut edges: Vec<(SymbolId, SymbolId)> = Vec::new();
    for (fid, fp) in file_parses.iter().enumerate() {
        let base = file_sym_base[fid];
        for call in &fp.calls {
            let caller = base + call.caller_local;
            if (caller as usize) >= symbols.len() {
                continue;
            }
            let callee_spur = interner.get_or_intern(&call.callee);
            if let Some(&d) = by_qual.get(&callee_spur) {
                edges.push((caller, d));
                continue;
            }
            let last = call.callee.rsplit("::").next().unwrap_or(&call.callee);
            let last_spur = interner.get_or_intern(last);
            if let Some(cands) = by_name.get(&last_spur) {
                if cands.len() == 1 {
                    edges.push((caller, cands[0]));
                }
                // Ambiguous: drop the edge rather than guess.
            }
        }
    }
    edges.sort_unstable();
    edges.dedup();

    Merged {
        sources,
        symbols,
        edges,
    }
}

pub(crate) fn parse_workspace(root: &Path, interner: &Interner) -> Merged {
    let file_parses = walk_and_parse(root);
    merge(file_parses, interner)
}
