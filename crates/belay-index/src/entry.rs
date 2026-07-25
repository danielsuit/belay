//! Entry-point detection.
//!
//! `syn` has no type resolution, so detection is a heuristic over attributes
//! and parameter type *paths* — the text of `axum::extract::Path<…>`, not a
//! resolved trait. The `/entrypoints` command dumps the detection reason, which
//! is the top debugging command precisely because this is heuristic.
//!
//! Heuristic tiers, first hit wins:
//!   1. `fn main` — the binary entry.
//!   2. A handler attribute macro: `#[get("/")]`, `#[post(..)]`, `#[route(..)]`,
//!      `#[axum::debug_handler]`, `#[rocket::get]`, …
//!   3. A parameter whose type path names a known extractor (`axum::extract::*`,
//!      `actix_web::*`, `warp::Filter`, `tide::Request`, …).

const HTTP_METHOD_MACROS: &[&str] = &[
    "get", "post", "put", "delete", "patch", "head", "options", "trace", "connect", "route",
    "routes", "debug_handler", "endpoint",
];

const EXTRACTOR_FRAGMENTS: &[&str] = &[
    "axum", "actix_web", "rocket", "warp", "tide", "poem", "salvo",
];

/// Well-known bare extractor type names (used when the path is unqualified,
/// e.g. `Path<…>` in a file that `use axum::extract::Path`).
const EXTRACTOR_TYPES: &[&str] = &[
    "Path", "Query", "State", "Json", "Form", "Header", "TypedHeader", "Extension", "Request",
    "Bytes", "Cookie", "Query", "Payload", "Multipart", "ConnectInfo", "OriginalUri",
];

/// Classify a function as an entry point. Returns the human-readable reason
/// or `None`.
///
/// `attrs` are the last-segment names of the fn's attributes.
/// `param_types` are the rendered type paths of its value parameters
/// (e.g. `"axum::extract::State<AppState>"`, `"Path<Id>"`, `"String"`).
pub fn classify_fn_entry(name: &str, attrs: &[String], param_types: &[String]) -> Option<String> {
    if name == "main" {
        return Some("fn main".to_string());
    }

    for a in attrs {
        let last = a.rsplit("::").next().unwrap_or(a);
        if HTTP_METHOD_MACROS.contains(&last) {
            return Some(format!("handler attribute #[{a}]"));
        }
    }

    for ty in param_types {
        let frag = EXTRACTOR_FRAGMENTS
            .iter()
            .find(|f| ty.contains(**f));
        if let Some(f) = frag {
            return Some(format!("extractor parameter `{ty}` ({f})"));
        }
        let head = ty.split(['<', ' ', '&', '(']).next().unwrap_or(ty);
        let head = head.rsplit("::").next().unwrap_or(head);
        if EXTRACTOR_TYPES.contains(&head) && ty != "String" {
            return Some(format!("extractor parameter `{ty}`"));
        }
    }

    None
}
