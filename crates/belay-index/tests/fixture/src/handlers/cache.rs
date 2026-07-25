// Fixture: a small gateway-shaped module the index tests parse.
// Not built; only parsed by `syn`. Shapes: an axum handler with extractor
// params, a call chain handler -> service -> repo, and a mutual-recursion
// cycle so the SCC test has a real SCC to condense.

pub struct AppState {
    pub tenant: String,
}

pub fn cache_get(state: axum::extract::State<AppState>, path: axum::extract::Path<u64>) -> String {
    let id = path.0;
    let v = service::lookup(&state, id);
    v
}

mod service {
    pub fn lookup(state: &super::AppState, id: u64) -> String {
        let row = super::repo::fetch(id);
        if row.is_empty() {
            return fallback(id);
        }
        row
    }

    pub fn fallback(id: u64) -> String {
        // mutual recursion: fallback -> lookup -> fallback (when row empty)
        lookup(&super::AppState { tenant: "x".into() }, id)
    }
}

mod repo {
    pub fn fetch(id: u64) -> String {
        format!("row-{id}")
    }
}

pub fn main() {
    let s = AppState { tenant: "t".into() };
    let _ = cache_get(axum::extract::State(s), axum::extract::Path(1));
}
