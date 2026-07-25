# belay — Plan

An interactive terminal security agent for Rust codebases. You type `belay`, you get a session. **Part I** is the interactive architecture. **Part II** is the static core (index, taint, reachability, incrementality). **Part III** is the scheduling & cache-optimization layer — where the token bill is actually decided. **Part IV** is the statistical decision layer — calibration, sequential testing, and false-discovery control. **Part V** is the interactive plane and its latency budget. **Part VI** integrates every mathematical concept and names the more-optimal upgrades. **Part VII** is the sequenced build order.

> **Guiding principle:** the scarce resource is **tokens under a correctness constraint.** Every design choice maximizes *confirmed findings per token* subject to a **provable bound on the false discovery rate**. A scanner that finds everything and reports 400 things finds nothing, because nobody reads it.
>
> **Corollary:** the second scarce resource is **the reviewer's attention.** Once findings exist, the human is the bottleneck server in the queue. The output order is a scheduling problem with the same math as the scan order (§IV.7).
>
> **Non-goal:** general coding agency. No write tools, no bash, no refactoring. Read-only, semantic, and narrow — that is why it can be 100× cheaper than a general agent at this task.

---

## Contents

**Part I — Interactive Architecture**
- 1. Goals & Constraints · 2. Tech Stack · 3. Session Model · 4. Command Surface
- 5. Tool Surface · 6. Process & Task Topology · 7. Workspace Structure

**Part II — The Static Core**
- II.1 Index construction · II.2 Interning, CSR & memory layout · II.3 SCC condensation & 2-hop reachability
- II.4 IFDS interprocedural taint · II.5 Pointer analysis, cheaply · II.6 Slicing as minimum path cover
- II.7 Incrementality (salsa / dirty-set closure) · II.8 The MIR upgrade path

**Part III — Scheduling & Cache Optimization**
- III.1 The cost model · III.2 The prompt trie and DFS optimality · III.3 Offline caching (Belady, Landlord)
- III.4 Worker assignment as balanced tree partition · III.5 Budgeted submodular coverage
- III.6 Pandora's box: which candidates to pay for · III.7 Queueing, batching & the hedging/locality conflict

**Part IV — The Decision Layer**
- IV.1 Calibration · IV.2 SPRT and anytime-valid stopping · IV.3 Adaptive submodular question selection
- IV.4 Neyman–Pearson reporting · IV.5 FDR control · IV.6 Online FDR across commits
- IV.7 Conformal guarantees · IV.8 Near-duplicate collapse (MinHash/LSH) · IV.9 Fingerprint stability

**Part V — The Interactive Plane**
- V.1 Latency budget · V.2 Render loop & lock-free index · V.3 Watch mode · V.4 Speculative prefetch · V.5 Triage UX

**Part VI — The Math, Integrated (concept → fit → upgrade)**

**Part VII — Build Order**

**Part VIII — Crate Map & References**

---

# Part I — Interactive Architecture

## 1. Goals & Constraints

- **Rust only.** No Python anywhere, first-party or vendored. No shelling out to a coding agent.
- **Terminal-first.** `belay` with no args opens a session, the way `claude` does. `belay -p "…"` is one-shot for pipes and CI.
- **Own the loop.** Append-only context, never compacted, so the prefix stays byte-stable and suffix-aware routing pins a rollout to one worker for its lifetime.
- **Constrained decoding.** All structured output via xgrammar against a JSON schema on the Subconscious serving path — valid by construction, never valid-on-retry.
- **Grounded.** Every finding carries verified file bytes or it is discarded.
- **Deterministic.** Same commit + model + prompt hash ⟹ identical fingerprint set. Temperature 0, fixed seed, deterministic slice ordering.
- **Read-only.** No write/edit/bash tool exists in the binary.

## 2. Tech Stack

| Concern | Choice |
|---|---|
| Async runtime | `tokio` (multi-thread) |
| TUI | `ratatui` + `crossterm` |
| Parse | `syn` (full, visit, extra-traits) + `proc-macro2` (**`span-locations`**) |
| Parallel parse | `rayon` |
| Incremental compute | `salsa` |
| Interning | `lasso` (`ThreadedRodeo`) |
| Hash | `rustc-hash` (FxHashMap), `blake3` (content) |
| Bitsets | `fixedbitset`, `roaring` |
| Arena | `bumpalo` |
| Lock-free snapshot | `arc-swap` |
| Walk | `ignore` |
| File watch | `notify` (debounced) |
| HTTP | `reqwest` (rustls, http2) |
| Serde | `serde`, `serde_json`, `simd-json` (parse) |
| CLI | `clap` (derive) |
| Persistence | `redb` (session + index cache) |
| Allocator | `mimalloc` |
| Metrics | `hdrhistogram`, `tracing` |

## 3. Session Model

```
$ belay
  belay · subconscious/gateway · 51,204 LOC · index 340ms · 412 entry points
  cache warm · tim-qwen3.6-27b

  › _
```

**Startup path, budgeted at 400 ms:**

1. `redb` index cache hit → `mmap` and validate against file mtimes+hashes (≈40 ms). Miss → full parse (§II.1).
2. Fire the **prefix warm** request: the frozen system+taxonomy prefix with `max_tokens: 1` (§V.1). This is the single highest-leverage startup action — it converts the first real query's prefill from cold to hot.
3. Render prompt. Index finishes in the background if cold; commands that need it await a `tokio::sync::watch` ready signal.

**Session state** is one append-only transcript in `redb` under `session:{ulid}`:

```rust
struct Turn {
    hlc: u64,             // monotonic, survives restart
    role: Role,
    content: Block,       // Text | ToolCall | ToolResult | Finding
    prompt_hash: [u8; 8], // hash of everything before this turn
}
```

Append-only is not a storage decision, it is a **cache** decision. Compaction rewrites the prefix and voids every cached block downstream of the rewrite point. `/compact` exists, warns, and starts a new logical session that inherits only pinned findings.

`belay --resume` reattaches to the last session; `belay --resume {id}` to a specific one. Resumption replays the transcript into context verbatim, so the whole prefix is a cache hit — a resumed 60k-token session costs roughly one cold slice.

## 4. Command Surface

Bare text is a question, answered against the index with tools. Slash commands are local and never round-trip unless stated.

| Command | Effect |
|---|---|
| `/scan [path\|glob]` | full or scoped scan; streams findings into the inbox as they confirm |
| `/focus <sym\|path>` | pin a slice as the working set; subsequent questions are scoped to it |
| `/why <id>` | full refutation trace for a finding: reachability chain, tool calls, evidence ledger |
| `/triage` | enter the inbox: `a`ccept / `r`eject / `s`kip / `d`efer, vim keys, `u`ndo |
| `/entrypoints` | dump detected entry points with detection reason — **the top debugging command** |
| `/graph <sym>` | callers/callees, reachability from entry set |
| `/diff` | scan only what changed vs baseline commit |
| `/baseline [update]` | show or rewrite `.belay/baseline.json` |
| `/cost` | tokens in/out, cache hit rate, $ equivalent, per-phase breakdown |
| `/model <id>` | switch model mid-session (forks the session; prefix cache is model-scoped) |
| `/export <sarif\|json\|md>` | write report |
| `/watch` | ambient mode (§V.3) |

Non-interactive:

```
belay -p "is the cache key tenant-scoped?"        # one-shot, prints, exits
belay scan --format sarif --baseline .belay/baseline.json --fail-on high
belay index --dump-graph --dump-entry-points
belay eval --corpus corpus/rustsec.json
```

Exit codes: `0` clean · `1` new findings above `--fail-on` · `2` index/config error · `3` inference unavailable.

## 5. Tool Surface

Four semantic tools plus one escape hatch. All read-only, all O(1)-ish against the index.

```rust
read_span(path, start, end)        -> String
definition_of(symbol)              -> Option<SymbolRef>
callers_of(symbol)                 -> Vec<SymbolRef>        // reverse CSR, O(deg)
reaches(from, to)                  -> Option<Vec<SymbolRef>> // 2-hop label, O(|L|)
grep(pattern, glob?)               -> Vec<Match>            // escape hatch only
```

`reaches` is the tool a general coding agent cannot give you. With grep+glob a model reconstructs the call graph from text matches, badly, over many turns. Here it asks the reachability question directly and gets a witness path. This single tool is most of the turn-count reduction in Part IV.

Tool results are **content-addressed and memoized** per session: identical call → identical bytes → the model sees a stable repeated block, which the prefix cache also rewards.

## 6. Process & Task Topology

Single binary, single process.

```
main
├── input task        crossterm event stream → mpsc<Input>
├── render task       16 ms tick, reads ArcSwap<Index> + AppState, no awaits on I/O
├── index task        rayon parse pool → builds Index → ArcSwap::store
├── watch task        notify → debounce 120 ms → dirty set → incremental reindex
└── engine
    ├── pass-1 pool   Semaphore(N_p1)  fan-out, stateless, one call per slice
    ├── pass-2 pool   Semaphore(N_p2)  agentic, stateful, SPRT-terminated
    └── writer        verify → dedup → FDR gate → inbox (bounded mpsc)
```

Rendering never blocks on inference. `ArcSwap<Arc<Index>>` gives readers a lock-free consistent snapshot while a rebuild swaps a new one in — no reader ever waits on the indexer.

`N_p1` is sized from Little's Law against fleet capacity, not guessed (§III.7).

## 7. Workspace Structure

```
belay/
  crates/
    belay-index/     parse · symbols · CSR graph · SCC · 2-hop labels · salsa
    belay-taint/     IFDS solver · lattice · transfer functions · entry/sink specs
    belay-plan/      prompt trie · scan order · worker partition · budget solver
    belay-engine/    client · prompt assembly · pass1 · pass2 loop · SPRT
    belay-stat/      calibration · FDR · conformal · MinHash/LSH · fingerprints
    belay-tui/       ratatui widgets · inbox · streaming renderer
    belay-report/    SARIF · markdown · terminal
    belay-eval/      RustSec corpus · metrics · bootstrap CI · Hyperband
    belay-cli/       clap · session · wiring       → binary `belay`
```

---

# Part II — The Static Core

Everything the model is asked is a question about this structure. Index quality caps scan quality; no prompt fixes a missing edge.

## II.1 Index construction

`ignore::WalkBuilder` → `rayon` parallel `syn::parse_file` → per-file partial index → merge.

**`proc-macro2` requires the `span-locations` feature or every span is line 0.** Verify on day one; it is the most common way this build stalls silently.

Budget: 50k LOC in **< 400 ms cold**, < 50 ms warm, < 5 ms for a single-file incremental. Parse dominates; the merge is a concat of preallocated vectors.

## II.2 Interning, CSR & memory layout

Data-oriented, not pointer-chasing:

- **Interning.** `lasso::ThreadedRodeo` → every module path, symbol name, and type name is a `u32` `Spur`. Symbol comparison is integer comparison. On a real workspace this is a 6–10× memory reduction over `String` fields, and it makes `FxHashMap<Spur, _>` lookups nearly free.
- **Spans as byte offsets**, not strings. `(FileId: u32, start: u32, end: u32)` = 12 bytes. Source files are `mmap`ed; `read_span` is a slice, never a read.
- **Call graph in CSR.** Two `Vec<u32>`: `offsets[n+1]`, `targets[m]`. Forward and reverse both materialized. BFS over CSR is a linear scan of contiguous memory — the whole point. An adjacency `HashMap<SymbolId, Vec<SymbolId>>` is 20–40× slower to traverse and there is no reason to pay it.
- **Bitsets.** `fixedbitset` for per-query visited sets (reused across queries via a generation counter, never reallocated); `roaring` for persisted reachability sets, which are large and sparse.
- **Arena.** `bumpalo` per parse-file task; the whole per-file scratch dies in one `drop`.

## II.3 SCC condensation & 2-hop reachability

Call graphs have cycles. Condense first:

1. **Tarjan SCC** → condensation DAG, O(V+E). Recursion in mutual-recursion clusters collapses to one node, which is also semantically right: anything reachable from one member is reachable from all.
2. **2-hop labeling** (Cohen et al.) over the DAG, built by **pruned landmark labeling** (Akiba et al.): each node `v` gets `L_in(v)`, `L_out(v)`. Then

```
reaches(u,v)  ⟺  L_out(u) ∩ L_in(v) ≠ ∅
```

Query is a sorted-set intersection, typically a handful of `u32` comparisons. Label size on sparse call graphs is small; cap it and fall back to bounded BFS above the cap.

Why this matters: `reaches` is called on every pass-2 turn and on every entry-point relevance test during planning. Naive BFS per query is O(V+E) each and turns planning into the slow part of an LLM-bound program, which is embarrassing. Full transitive closure is O(V·E) memory. 2-hop is the correct middle.

**Bit-parallel BFS** for the bulk case: pack 64 source nodes into a `u64` mask per vertex and propagate 64 BFS frontiers per traversal. One pass computes reachability from 64 entry points simultaneously. With 412 entry points that is 7 passes instead of 412.

## II.4 IFDS interprocedural taint

**Do not send the model anything the static layer can already rule out.** A slice with no taint path from any entry point to any sink is not a scan candidate, and pruning it costs microseconds instead of 6k tokens.

**IFDS** (Reps–Horwitz–Sagiv) solves interprocedural, finite, distributive subset problems as graph reachability on an *exploded supergraph*, in **O(E·D³)** where `D` is the domain size. Taint is exactly such a problem: the domain is the finite set of tracked facts, the transfer functions are distributive.

```
Lattice:    L = 2^{Facts}, ordered by ⊆, join = ∪
Facts:      TaintedVar(local) | TaintedField(place) | Attacker(source_id)
Transfer:   gen/kill per statement kind
Solution:   MFP via worklist ≡ MOP, since transfer functions distribute
```

Kleene iteration to the least fixed point terminates because `L` is finite and transfers are monotone (**Knaster–Tarski**). Same `MonotoneSolver<L>` shape as any dataflow engine — implement once, reuse for the reaching-`unsafe` analysis and the panic-reachability analysis.

Sources: request extractors, `Deserialize` inputs, env, argv, socket reads. Sinks: the taxonomy's sink table (§IV.0). Sanitizers: explicit allow-list, per class.

**Expected effect.** On the gateway, this is the difference between 1,200 candidate slices and roughly 200–350. It is the single largest cost multiplier in the design, and it is free relative to a token.

## II.5 Pointer analysis, cheaply

Taint through references needs aliasing. Two classical options:

| | Complexity | Precision |
|---|---|---|
| **Steensgaard** (unification, union-find) | ~O(n·α(n)) | coarse |
| **Andersen** (inclusion, constraint graph) | O(n³) | finer |

**Rust changes the calculus.** `&mut` exclusivity means an active mutable borrow has no other live alias, so the points-to sets that would blow up in C are already constrained by the borrow checker. Steensgaard-level unification is adequate for `&`/`&mut`/`Box`, and the residual imprecision concentrates in `Rc<RefCell<_>>`, raw pointers, and `unsafe` — which are exactly the places you *want* over-approximation and a model's attention anyway.

Ship Steensgaard. Track `Rc`/`RefCell`/raw as "opaque, assume aliased," and let that pessimism route those slices to the model rather than silently dropping them.

## II.6 Slicing as minimum path cover

A BFS ball of depth 2 around an entry point is a blob: the model reads a set of functions and has to reassemble control flow. A **chain** — a linear call sequence — reads like a straight-line program and is dramatically easier to reason about, and it is also more compressible in the prompt trie (§III.2).

**Minimum vertex-disjoint path cover of a DAG** = `|V| − |maximum bipartite matching|` in the split graph (Dilworth / König). Compute the matching with **Hopcroft–Karp** in O(E√V).

```
for each taint-reachable subgraph G_t of the condensation DAG:
    split each v into (v_out, v_in)
    edge (u,v) ∈ G_t  →  (u_out, v_in)
    M = hopcroft_karp()
    chains = decompose(M)        # |V| − |M| chains, vertex-disjoint
```

Each chain is one scan unit: source → intermediate calls → sink, in order. Chains are vertex-disjoint by construction, so total scan volume equals total taint-reachable volume — **no duplicated tokens across slices**, which naive BFS balls cannot promise.

Where a chain exceeds the per-prompt token budget, split it at the **minimum-weight cut vertex** (the call site whose two sides are most balanced), and emit a one-line summary of the elided side. Deterministic: ties broken by `(file, line)`.

## II.7 Incrementality

Scanning every commit means re-deriving almost the same index forever.

**`salsa`** — the demand-driven incremental framework behind rust-analyzer. Model the index as queries: `parse(file) → ast`, `symbols(file)`, `calls(file)`, `graph()`, `scc()`, `labels()`, `taint(entry)`. A file edit invalidates `parse(f)` and everything transitively downstream, and nothing else. `salsa`'s durability tiers let you mark vendored/`target` inputs as high-durability so they never re-verify.

**Dirty-set closure.** When symbol `s` changes:

```
dirty = {s}
dirty ∪= reverse_reachable(s)     # a change here can alter reachability upstream
dirty ∪= callees(s) ∩ taint_frontier
rescan = { chain | chain ∩ dirty ≠ ∅ }
```

Reverse-reachable, not just direct callers: a change in `f` can make a pre-existing pattern in a *caller* newly reachable. Diff-based scanning that only looks at the diff hunk misses exactly this class, and it is a common one.

Note the honest counterweight: with a >98% cache hit rate, full rescan is often cheaper than the engineering cost of getting incrementality exactly right. Ship full-scan first, add incrementality when `/watch` makes latency the binding constraint.

## II.8 The MIR upgrade path

`syn` sees pre-expansion tokens. Consequences, stated plainly:

- `#[derive]` and attribute macros are opaque; generated impls are invisible.
- Any local codegen macro is a blind spot.
- No type information, so `definition_of` on a method call is name-based and can be wrong under trait dispatch.
- Const-eval, monomorphization, and drop order are invisible.

**Inventory your macro usage before committing to `syn`-level analysis.** If the blind spot is material, the upgrade is a `rustc` driver over **`stable_mir`** — real types, real MIR, real CFG, borrow information. Precision goes up enormously; build time goes from 400 ms to a full `cargo check`, and you inherit toolchain pinning.

Recommendation: `syn` for the interactive index (fast, always-on), optional MIR pass for `/scan --deep` and for CI. Two indexes behind one trait, chosen by cost. Prior art worth reading before designing this: MIRAI (abstract interpretation over MIR) and Rudra (ownership/panic-safety bug classes).

---

# Part III — Scheduling & Cache Optimization

This is where the money is. The model is fixed; what varies by 5–20× is **what you send and in what order**.

## III.1 The cost model

```
Cost = Σ_i [ (1 − h_i)·P_i·p_in  +  D_i·p_out ]
```

`P_i` prefill tokens, `D_i` decode tokens, `h_i` cache hit fraction, `p` unit prices. Decode is small and irreducible in pass 1 (a JSON object). **Everything interesting is `(1 − h_i)·P_i`**, and both factors are under your control:

- `P_i` ← static pruning (§II.4), chain slicing (§II.6), budget selection (§III.5)
- `h_i` ← prompt layout, scan order (§III.2), worker affinity (§III.4), eviction policy (§III.3)

**Illustrative arithmetic**, 51k LOC gateway:

| Stage | Prefill tokens |
|---|---|
| Naive: 1,200 BFS slices × 6k | 7.2 M |
| After IFDS pruning (→ ~300 chains) | 1.9 M |
| Chains vertex-disjoint (no re-send) | 1.4 M |
| Frozen 2k rubric prefix, cached across all | −0.6 M billed at hit rate |
| Trie-DFS ordering (shared call-chain prefixes) | **≈ 0.45 M effective** |

~16× against naive, before any model change. Treat the numbers as shape, not forecast; the point is the ratio between levers.

## III.2 The prompt trie and DFS optimality

Chains overlap at their heads — many handlers funnel into the same middleware, the same auth check, the same cache lookup. Build the **trie over chain token sequences** (frozen prefix → shared head → divergent tail).

**Claim.** If prompts form a trie and the cache holds at least the longest root-to-leaf path, then emitting prompts in **DFS pre-order** makes the total prefill exactly the number of distinct trie nodes, which is the information-theoretic minimum. Any ordering pays ≥ that; a bad ordering pays up to Σ|path| (the naive sum).

Proof sketch: under DFS, each trie edge is traversed as a "new token" exactly once, because the parent path is the immediately preceding prompt's prefix and is still resident. Any order that leaves a subtree and returns re-pays the path to it.

So: **scan order is a tree traversal, not a loop over files.** Deterministic tie-breaking on `(file, line)` keeps it reproducible run to run — which is what lets a *second* run be nearly free.

**Cache-size caveat.** If the cache cannot hold the longest path, DFS is no longer exactly optimal and you're in the general offline caching problem (§III.3). Depth-bounded DFS with the deepest subtrees visited first is the practical fix.

**Related structure worth noting:** this is the same radix-tree-over-token-sequences you already run inside sglang-router. The planner is building the router's tree in advance and choosing an order that walks it optimally. That is only possible because the workload is known ahead of time — which is the thing an interactive coding agent can never do and a batch scanner always can.

## III.3 Offline caching: Belady and Landlord

Interactive agents evict with LRU because the future is unknown. **In a scan, the future is fully known** — you computed the schedule in §III.2. That admits the offline optimum:

- **Belady's MIN** (1966): evict the block whose next use is furthest in the future. Optimal for **uniform-size, uniform-cost** blocks. Radix-tree pages at fixed page granularity are uniform-size, so MIN applies directly.
- **Variable-size or variable-cost** blocks make optimal offline caching **NP-hard** (general caching). Use **Landlord** (Young), which is k-competitive online and excellent offline, or LP-rounding if you ever care enough.

Practically: emit an eviction-hint stream alongside the scan schedule — `(block_hash, next_use_index)` — and have the router honor it. If the router does not accept hints, the DFS order alone gets most of the benefit, because DFS makes LRU behave nearly like MIN (the least-recently-used block genuinely is the furthest-future one under a tree walk).

## III.4 Worker assignment as balanced tree partition

With `W` workers, the wrong move is round-robin: every worker ends up with a copy of every shared prefix, and you multiply prefill by `W`.

**Right move: partition the trie into `W` connected subtrees of balanced token weight.** Each worker owns a subtree; the shared ancestor path is resident on exactly the workers that need it; cross-worker duplication is only the path above the cut.

```
minimize   max_j  weight(part_j)
subject to each part being a connected subtree
```

Min-max **balanced connected k-partition of a tree** is solvable by DP over subtree weights in O(n·W) for the decision version plus binary search on the bound; the classic bottom-up greedy (cut whenever accumulated weight ≥ total/W) is a 2-approximation and is 30 lines. Ship the greedy, keep the DP behind `--exact-partition` for benchmarking.

**Where load balance dominates instead** (short chains, homogeneous costs), plain **LPT list scheduling** (Graham) is makespan ≤ (4/3 − 1/(3m))·OPT and simpler. Choose by measuring the prefix-sharing coefficient: if the trie's internal-node token mass is < 20% of total, locality doesn't matter and you should just balance.

**Straggler handling: power-of-two-choices** for late, unassigned chains — sample two workers, queue on the shorter — giving `O(log log n)` max load without any central state.

## III.5 Budgeted submodular coverage

Under a token budget `B`, which chains do you scan? Chains overlap in the `(symbol, taint-class)` pairs they cover, so coverage is **monotone submodular**: the marginal value of a chain shrinks as related chains are already selected.

```
maximize   f(S) = |⋃_{i∈S} covered(i)|        (weighted by class severity × prior)
subject to Σ_{i∈S} cost(i) ≤ B
```

- **Greedy by marginal-gain-per-cost** gives ½(1 − 1/e).
- **Sviridenko's variant** (partial enumeration of the best 3 elements, then density greedy) gives **(1 − 1/e) ≈ 0.632**, and (1 − 1/e) is the best achievable in polynomial time unless P = NP.
- **CELF / lazy greedy** (Leskovec et al.): submodularity means a stale marginal gain is an upper bound, so a max-heap of gains needs only re-evaluation at the top. Typical 100–700× fewer evaluations. Use it; the plain greedy's O(n²) evaluations is the difference between 3 ms and 2 s of planning.

**Lagrangian view for the interactive case:** relax to "scan chain `i` iff `p_i · v_i ≥ λ · c_i`", bisect on `λ` to hit `B`. One float compare per chain, recomputable every keystroke — which is what `/focus` and `--budget` need.

## III.6 Pandora's box: which candidates to pay for

Pass 2 is expensive and sequential: you hold `k` candidates from pass 1, each with a calibrated value distribution `V_i` (severity × probability it confirms) and a known inspection cost `c_i` (expected turns × tokens). You may investigate in any order, and you may stop.

This is exactly **Pandora's box** (Weitzman 1979), and it has an **optimal index policy**:

```
reservation value σ_i solves   E[(V_i − σ_i)^+] = c_i
open boxes in decreasing σ_i
stop when   max value already confirmed  ≥  max σ_i among unopened
```

Optimal, not heuristic. It fuses severity, calibrated confidence, and expected investigation cost into one scalar and tells you when to stop paying — replacing "investigate everything above 0.7 confidence," which is neither.

*Refinement:* candidates are not independent (confirming a tenant-isolation bug in the cache module raises the prior on its neighbors). Independence is Weitzman's assumption. The correct generalization is a **correlated Pandora's box / Bayesian-network prior**, which is intractable in general; the practical fix is a **class-and-module prior updated after each confirmation**, re-solving σ after each open. Note it as an approximation rather than pretending it isn't one.

## III.7 Queueing, batching & the hedging/locality conflict

**Little's Law sizes the pool.** With mean per-slice latency `W` and target throughput `X`, in-flight concurrency `L = X·W`. For 300 chains at 8 s each and a 90 s target wall-clock, `L ≈ 27`. Set `N_p1 = 27`, not 200. Oversubscribing past the fleet's continuous-batching capacity does not increase throughput; it increases queueing delay and blows up the tail.

**Kingman's approximation** for the tail:

```
E[W_q] ≈ (ρ/(1−ρ)) · ((c_a² + c_s²)/2) · τ
```

The `ρ/(1−ρ)` term is why targeting ρ ≈ 0.95 is a mistake — it is 19× the mean service time in queue, versus 4× at ρ = 0.8. For a batch scan, run hot. For the interactive path, keep a **reserved low-utilization lane** so a typed question never queues behind a scan.

**The hedging trap.** *The Tail at Scale* says hedge the slow request to a second replica. Here that is often wrong: a hedge to a different worker is a **guaranteed cache miss**, so you pay full prefill to save tail latency you might not have had. Policy:

- Interactive turns: hedge at p95, accept the miss — human latency dominates.
- Scan chains: **do not hedge across workers.** Re-queue on the *same* worker, or hedge only if the chain's prefix is short enough that the miss is cheap (`P_i < θ`).

**Batch grain.** Per-request overhead vs. head-of-line delay is a convex tradeoff with the familiar square-root solution:

```
minimize  C_fixed/(k) + C_delay·k     ⟹     k* ∝ √(C_fixed / C_delay)
```

Small `k` for interactive, large `k` for scan. One knob, two profiles.

---

# Part IV — The Decision Layer

A scanner runs thousands of hypothesis tests. Treating each in isolation with a confidence threshold is the reason scanners are noisy. The right frame is **multiple testing with error-rate control**.

## IV.0 Taxonomy (the rubric is the product)

Generic CWE lists produce generic noise. Weighted toward a multi-tenant inference gateway, each class carrying `{sources, sinks, sanitizers}` for the IFDS layer and a frozen rubric paragraph plus one positive/one negative exemplar for the prompt prefix.

| Class | Meaning here |
|---|---|
| `tenant-isolation` | cache key, radix key, or routing decision not scoped by tenant/org |
| `cache-poisoning` | attacker-influenced prefix/suffix that can collide across tenants |
| `authz-missing` | handler reachable without a key/permission check on the path |
| `accounting-integrity` | token/micro-unit arithmetic that can wrap, overflow, or double-settle |
| `inflight-race` | two-phase billing state reachable in a non-crash-safe interleaving |
| `resource-unbounded` | no cap on body size, channel depth, concurrency, upstream timeout |
| `panic-on-input` | `unwrap`/`expect`/index/slice on request-derived data |
| `unsafe-soundness` | `unsafe` block whose invariant isn't established by its callers |
| `ssrf-upstream` | upstream URL or worker target influenced by request content |
| `secret-exposure` | key/token in logs, error bodies, `Debug` impls, metric labels |
| `injection` | SQL, command, header, log |
| `deser-bomb` | unbounded allocation from deserialization or decompression |

Frozen after M2. Every edit to this block invalidates the cached prefix for every future scan and every stored calibration, so version it (`rubric_v3`) and record the version in every finding.

## IV.1 Calibration

Raw model confidence is not a probability. Everything downstream — SPRT thresholds, Pandora σ, FDR p-values — requires `P(vuln | evidence)` to actually mean what it says.

Fit on the RustSec corpus (§VII-M3), per class:

- **Platt scaling**: `p = σ(a·s + b)`, two parameters, works on small calibration sets.
- **Isotonic regression**: nonparametric, monotone, better with ≥ 500 labeled points; PAVA is O(n).
- Report **ECE** (expected calibration error, 10 bins) and a reliability diagram. Target ECE < 0.05.

Recalibrate on every model or rubric change. Store `(model_id, rubric_version) → calibrator` and refuse to run FDR control with a missing or stale calibrator — a wrong `p` silently voids every guarantee below it.

## IV.2 SPRT and anytime-valid stopping

"Turn cap 8" is a guess. The principled version: each pass-2 turn yields evidence `e_n`; accumulate the log-likelihood ratio.

```
Λ_n = Σ_{i≤n} log[ P(e_i | vuln) / P(e_i | benign) ]

accept  if  Λ_n ≥ log((1−β)/α)
reject  if  Λ_n ≤ log(β/(1−α))
else continue
```

**Wald's SPRT** minimizes expected sample size among all tests with error rates `(α, β)` for simple hypotheses (Wald–Wolfowitz). You set the error rates you want and the *turn count falls out* — easy candidates die in 2 turns, hard ones get 12.

**The honesty caveat, and the fix.** SPRT optimality assumes i.i.d. evidence; consecutive tool calls in one rollout are strongly dependent, so the nominal `α` is not the real `α`. The rigorous replacement is a **test martingale / e-value**: maintain a nonnegative process `M_n` with `E[M_n | F_{n−1}] ≤ M_{n−1}` under the null, and stop when `M_n ≥ 1/α`. **Ville's inequality** gives `P(∃n : M_n ≥ 1/α) ≤ α` — valid at *any* stopping time, under dependence, with no i.i.d. assumption. This is strictly the correct tool and is barely more code.

Ship SPRT thresholds as the interface; implement the accumulator as an e-process. Keep a hard turn ceiling of 16 as a cost guard, not as the decision rule.

## IV.3 Adaptive submodular question selection

Which tool should the model call next? Left free, models wander. The objective is **expected information gain**:

```
next* = argmax_t  I(V ; answer_t | history)
      = argmax_t  H(V | history) − E_a[ H(V | history, answer_t = a) ]
```

Under **adaptive submodularity** (Golovin & Krause), the greedy adaptive policy is within **(1 − 1/e)** of the optimal adaptive policy — the direct generalization of the submodular greedy bound to the sequential, feedback-driven case. Information gain for a noisy-OR evidence model is adaptive submodular, which covers the taint-witness structure here.

Implementation without a second model call: precompute for each pending question an expected-gain estimate from the calibration corpus (how much did `callers_of` vs `read_span` move the posterior historically, by class), and inject the top-3 as a *suggested next step* in the turn prompt. Cheap, and it collapses the wandering that dominates turn count.

Equivalently: this is **generalized binary search** with costs. Framing it that way makes the goal explicit — every turn should approximately halve the hypothesis space, and a turn that cannot is a turn the model shouldn't take.

## IV.4 Neyman–Pearson reporting

At a fixed acceptable false-positive rate, the **most powerful** test is a likelihood-ratio threshold — the NP lemma. So the report threshold is not a tuned confidence number, it is `Λ ≥ τ` with `τ` set by the operating point you choose on the corpus ROC.

Two profiles, both derived rather than guessed:

| Profile | Operating point |
|---|---|
| `--ci` | FP rate ≤ 0.02 per KLOC; maximize recall subject to that |
| `--audit` | recall ≥ 0.90; accept the resulting FP rate |

Print the achieved point from the last eval run in `/cost`, so the operator sees what they actually chose.

## IV.5 FDR control

A 51k-LOC scan runs ~300 chain-level tests. At a per-test FP rate of 5% that is 15 false findings even if the tool is working perfectly. Per-test control is the wrong guarantee. Control the **false discovery rate** — the expected fraction of reported findings that are wrong.

**Benjamini–Hochberg:** sort `p_(1) ≤ … ≤ p_(m)`, take

```
k* = max{ k : p_(k) ≤ k·q/m },  reject the k* smallest
```

which controls FDR ≤ `q` under independence or positive dependence (PRDS).

Findings here are **not** independent or reliably PRDS — one bad prompt correlates errors across every chain in a module. Options:

- **Benjamini–Yekutieli**: valid under arbitrary dependence, costs a `Σ1/i ≈ ln m` factor of power. Conservative and safe.
- **e-BH** (Wang & Ramdas): feed the e-values from §IV.2 directly, controls FDR under **arbitrary dependence** with no log penalty. Since the pipeline already produces e-values, this is the natural choice and strictly better than BY here.

Report `q` in the header: *"14 findings at FDR ≤ 0.10 — expect ~1.4 false."* That sentence is worth more to a reviewer than any per-finding confidence score.

**Storey's π₀** estimator (proportion of true nulls) recovers power when most chains are clean, which is the normal case: adaptive BH with `q/π̂₀` instead of `q`.

## IV.6 Online FDR across commits

In CI the tests never stop — a new batch every commit, forever. Per-run FDR control doesn't bound the error rate of the *stream*.

**Alpha-investing / LORD++** (Foster–Stine; Javanmard–Montanari): maintain an alpha-wealth `W_t`; each test spends `α_t ≤ W_t`; each rejection earns wealth back. This controls FDR over an infinite stream of tests with no fixed `m`.

Consequences that fall out and are genuinely useful:

- A scanner producing many confirmed true findings **earns the right to be more aggressive** — wealth accumulates.
- A scanner on a long clean streak automatically becomes conservative — which is correct, because a finding after 300 clean commits is a priori less likely than one after a big refactor.
- Wealth is persisted next to the baseline and is part of the repo's scan state.

## IV.7 Conformal guarantees

For the class of user who asks "how sure are you," give a distribution-free answer.

**Split conformal:** with `n` calibration points and nonconformity score `s`, the threshold is the `⌈(n+1)(1−α)⌉`-th smallest calibration score. The resulting prediction set has **marginal coverage ≥ 1 − α** with no assumption about the model beyond exchangeability.

Applied: `/scan --coverage 0.9` returns a finding *set* guaranteed (marginally, over the corpus distribution) to contain the true vulnerabilities 90% of the time. Set size is the honest cost — a small set means the tool is confident, a large one means it isn't, and both are useful information. **Conformal risk control** (Angelopoulos et al.) extends this to bounding expected miss count rather than coverage.

Exchangeability is the assumption that bites: your repo is not drawn from the RustSec distribution. Report conformal sets with that caveat attached, and refresh calibration with accepted/rejected triage decisions from actual use (§V.5) — which is the real path to a calibrator that fits *your* code.

## IV.8 Near-duplicate collapse

The same pattern in 40 handlers is one finding with 40 sites, not 40 findings. Reviewer attention is the scarce resource (guiding-principle corollary), and 40 rows spend it 40×.

- **Shingle** the normalized span (`w = 5` token shingles).
- **MinHash** signature, `k = 128` permutations → Jaccard estimate with standard error `1/√k ≈ 0.088`.
- **LSH banding**, `b` bands of `r` rows: collision probability `1 − (1 − s^r)^b`, sharp threshold at `≈ (1/b)^{1/r}`. For a target similarity of 0.8: `r = 5, b = 20` gives a clean S-curve.
- Cluster, report the representative with a site count, expand on demand in `/why`.

Cost: O(n·k) hashing, O(n) bucketing. Effect on a real codebase: routinely 3–5× fewer rows to read.

## IV.9 Fingerprint stability

```rust
fn fingerprint(f: &Finding) -> [u8; 16] {
    blake3(&[ f.class, f.rubric_version, &cdc_normalized(&f.span) ].concat())
}
```

**Content-defined chunking** (Rabin / FastCDC) rather than fixed normalization: chunk boundaries are determined by content, so inserting a line above the finding shifts nothing downstream. Fixed-offset fingerprints break on every reformat and make the baseline useless within a week — this is the difference between a tool people keep and one they delete.

Three fingerprints per finding, matched in order: `(class, path, span)` exact → `(class, span)` survives file moves → `(class, enclosing_symbol)` survives edits within the function. Report the weakest match level used, so a "matched at level 3" finding is visibly a fuzzy match.

Store the baseline as a **cuckoo filter** when it exceeds ~10⁵ entries: better lookup locality and deletion support versus a Bloom filter at the same FP rate. Below that, a plain sorted `Vec` beats both — do not over-engineer the small case.

---

# Part V — The Interactive Plane

## V.1 Latency budget

Enforce with deadline propagation; measure from **keystroke**, not from service entry (coordinated omission).

| Action | p99 budget | Mechanism |
|---|---|---|
| keystroke → render | 16 ms | render task never awaits I/O |
| `/entrypoints`, `/graph`, `/focus` | 5 ms | pure index queries, 2-hop labels |
| single-file reindex on save | 50 ms | salsa dirty-set, one `syn::parse_file` |
| question → **first token** | 250 ms | pre-warmed prefix + reserved lane |
| pass-1 chain completion | 8 s | fleet-dependent |
| full `/scan`, 50k LOC | 90 s | `L = X·W` concurrency (§III.7) |
| `/why` full trace render | 30 ms | cached, no inference — the trace was stored at confirm time |

**Prefix pre-warming is the highest-leverage line in this table.** At session start, before the user types, send the frozen prefix with `max_tokens: 1`. The first real question then prefills from cache and hits the 250 ms budget instead of missing it by a second. Re-warm after `/model` and after any rubric change.

**Where the tail actually is:** an inference call is seconds; a 5 ms index query is rounding error. Micro-optimizing the index matters for `/watch` and for planning-loop iteration counts (§III.5's CELF), not for perceived latency of a question. Spend effort accordingly.

## V.2 Render loop & lock-free index

```rust
struct App {
    index: Arc<ArcSwap<Index>>,   // readers never block; writer swaps a new snapshot
    stream: Option<TokenStream>,  // in-flight assistant turn
    inbox: FindingInbox,
    metrics: Metrics,
}
```

- Render at 60 Hz off a `tokio::time::interval`, reading `index.load()` — an atomic pointer read.
- Streaming tokens go into a `String` the renderer reads; **never** re-render the whole scrollback per token. `ratatui`'s diffing handles the terminal write, but the *layout* of finished turns should be cached — pre-wrap finished turns once and store the line vector.
- Syntax highlighting is the classic frame-budget killer. Highlight lazily, only the visible viewport, and memoize per `(span, theme)`.
- Backpressure: a bounded `mpsc(1024)` from engine → UI. On lag, coalesce — drop intermediate progress events, never drop findings.

## V.3 Watch mode

```
notify → debounce 120 ms → hash changed files → salsa invalidate
       → dirty-set closure (§II.7) → re-run IFDS on affected entries
       → rescan only chains intersecting the dirty set
       → new findings appear in the inbox
```

Debounce matters: editors write-then-rename and emit 3–6 events per save. Hash before invalidating — a save that changes nothing (formatter no-op) should cost zero.

Rate-limit ambient scanning to a **token-bucket** so `/watch` cannot run away with the budget while you're at lunch. Default: 50k prefill tokens per 10 minutes, burst 200k, `/cost` shows the drain.

## V.4 Speculative prefetch

While the user reads a finding, the fleet is idle and the cache is warm. Prefetch the chains they are most likely to ask about next.

Predict with a **first-order Markov model over navigation events** — `(current finding class, current module) → next viewed`, learned from the session log. Prefetch the top-`k` under a strict budget cap, and only into a **low-priority lane** that a real question preempts.

This is the same locality argument as the trie: a prefetch that lands keeps you on the warm path; a prefetch that misses cost you idle capacity you weren't billing for anyway. Cap it, measure hit rate in `/cost`, and turn it off if the hit rate is under ~30%.

## V.5 Triage UX

`/triage` is a queue with a scarce server (the human). Schedule it correctly.

**Gcµ rule.** Serve `argmax_i c_i(t) · μ_i` where `c_i` is holding cost and `μ_i` the service rate:

```
c_i(t) = severity_i × p_i × age_factor_i(t)
μ_i    = 1 / expected_review_seconds_i
```

The c-µ rule is provably optimal for a multiclass queue with linear holding costs — exactly this setting — and is one multiply. Cheap, correct, and it means a high-severity finding with a short clear trace is shown before a medium one requiring 10 minutes of reading, which is what a good reviewer does by instinct anyway.

**Type-specific aging** so nothing starves:

```
f_critical(t) = κ·t                  (linear — an open critical is linearly worse)
f_low(t)      = κ·(1 − e^{−t/τ})     (saturating — an old low-sev isn't urgent)
```

**Triage decisions are training data.** Every accept/reject is a labeled point. Write them to `.belay/labels.jsonl` and fold them into the calibrator (§IV.1). After a few hundred decisions the calibration is fit on *your* codebase rather than RustSec, and the conformal exchangeability caveat (§IV.7) substantially weakens. This is the closest thing the design has to a compounding advantage — the tool gets sharper on your repo specifically the more you use it.

---

# Part VI — The Math, Integrated (concept → fit → upgrade)

Every concept keeps a home. Where a cheaper or stronger tool exists it's named as the upgrade, with the original retained as an analytical lens.

## VI.1 Static core

| Concept | Home | Note |
|---|---|---|
| **Tarjan SCC** | condensation before any reachability | recursion clusters collapse correctly |
| **2-hop labeling / PLL** | `reaches()` tool, planner relevance | O(1)-ish vs O(V+E) BFS per query |
| **Bit-parallel BFS** | bulk reachability from all entry points | 64 sources per pass |
| **IFDS** (Reps–Horwitz–Sagiv) | pre-model taint pruning | O(E·D³); the biggest cost multiplier in the design |
| **Knaster–Tarski / Kleene** | `MonotoneSolver<L>` shared by all dataflow passes | one solver, three analyses |
| **Steensgaard unification** | aliasing | Rust's `&mut` exclusivity makes Andersen's O(n³) unnecessary |
| **Dilworth / König + Hopcroft–Karp** | chain slicing via min path cover | vertex-disjoint ⟹ zero duplicated tokens |

## VI.2 Scheduling & cache — keep the trie, upgrade the eviction

| Keep | Upgrade | Why |
|---|---|---|
| Trie-DFS scan order | keep — provably minimal prefill under a tree prefix relation | the core result of Part III |
| LRU (router default) | **Belady MIN** with an emitted hint stream | the schedule is known offline; LRU is the online concession you don't need |
| Belady (uniform blocks) | **Landlord** if page sizes vary | general caching is NP-hard with variable size |
| Round-robin worker assignment | **balanced connected tree partition** | round-robin multiplies shared prefixes by `W` |
| — | **LPT list scheduling** when sharing < 20% | (4/3 − 1/3m) makespan; simpler when locality is absent |
| — | **Power-of-two-choices** for stragglers | log log n max load, no central state |
| Density greedy for budget | **Sviridenko (1 − 1/e)** + **CELF lazy greedy** | tight bound; 100–700× fewer marginal-gain evaluations |
| "investigate above 0.7" | **Pandora's box / Weitzman index** | optimal sequential inspection under cost; tells you when to stop |
| Fixed batch size | **√(C_fixed/C_delay)** grain, per profile | one convex tradeoff, two operating points |
| Hedged requests | **conditionally disabled on the scan path** | a cross-worker hedge is a guaranteed cache miss |

## VI.3 Decision layer — keep the loop, upgrade the guarantee

| Keep | Upgrade | Why |
|---|---|---|
| Raw model confidence | **Platt / isotonic calibration** | every downstream guarantee needs a real probability |
| Fixed turn cap (8) | **SPRT** → **e-process + Ville** | SPRT minimizes expected turns; e-values stay valid under the dependence SPRT assumes away |
| Free-form tool choice | **adaptive-submodular greedy** (Golovin–Krause) | (1 − 1/e) of the optimal adaptive policy; collapses wandering |
| Confidence threshold | **Neyman–Pearson likelihood ratio** | most powerful test at a chosen FP rate |
| Per-finding FP rate | **BH → e-BH** FDR control | 300 tests at 5% is 15 false findings on a working tool |
| — | **Storey π₀** adaptive BH | recovers power when most chains are clean |
| Per-run FDR | **LORD++ / alpha-investing** | CI is an infinite stream of tests |
| "confidence 0.85" | **split conformal**, `--coverage` | distribution-free marginal coverage |
| Exact-match dedup | **MinHash + LSH banding** | 40 sites collapse to one row |
| Fixed-offset fingerprints | **content-defined chunking (FastCDC)** | fingerprints survive reformatting; baselines survive the week |
| Bloom baseline | **cuckoo filter** above 10⁵ | deletion + better locality; plain `Vec` below |

## VI.4 Interactive plane

| Concept | Home |
|---|---|
| **Little's Law** `L = X·W` | pass-1 pool sizing, not a guessed constant |
| **Kingman** | why the interactive lane runs at ρ ≈ 0.7 and the scan lane at ρ ≈ 0.95 |
| **Gcµ rule** (Cox–Smith, Van Mieghem) | triage inbox ordering — the human is the scarce server |
| **Type-specific aging** | anti-starvation in the inbox, feeding `c_i(t)` |
| **Markov navigation model** | speculative prefetch during reading |
| **Token bucket** | ambient `/watch` budget cap |
| **Coordinated omission** | measure from keystroke |

## VI.5 Evaluation

| Concept | Home |
|---|---|
| **Stratified sampling** by class | corpus construction; no class under 5 instances |
| **Common random numbers** | same slices, same seed across variants — variance reduction on the *difference* |
| **Paired bootstrap** (10k resamples) | CI on Δdetection between prompt variants |
| **Successive halving / Hyperband** | prompt-variant selection under a fixed eval budget |
| **Best-arm identification** (LUCB) | when you need a guarantee, not just a winner |
| **McNemar's test** | paired binary outcomes on the same corpus items |

The rule that makes this worth building: **never accept a prompt change whose bootstrap CI on Δdetection includes zero.** Without it you are tuning against noise, and prompt tuning against noise is how scanners rot.

---

# Part VII — Build Order

Each step independently testable. Verification gates are not optional — they are how you learn the index is wrong before you spend tokens on it.

### M0 — `belay-index`: parse, symbols, spans
`ignore` walk, rayon `syn::parse_file`, interner, `mmap` sources, byte-offset spans, `redb` cache.
**Verify:** spans line-accurate on a 200-file crate (property test against `rustfmt`-stable reparse); cold index of 50k LOC < 400 ms; warm < 50 ms; `span-locations` confirmed on.

### M1 — Graph, SCC, labels, entry points
CSR forward+reverse, Tarjan condensation, 2-hop labels with size cap, bit-parallel BFS, entry-point detection.
**Verify:** every axum handler in the gateway detected and the list eyeballed via `/entrypoints`; `reaches()` agrees with brute-force BFS on 10⁵ random pairs; label build < 100 ms.

### M2 — `belay-taint`: IFDS
`MonotoneSolver<L>`, gen/kill per statement kind, Steensgaard aliasing, source/sink/sanitizer specs per class.
**Verify:** on 20 hand-planted taint flows, zero false negatives (soundness first — a missed flow is never scanned); candidate-chain count drops ≥ 3× vs. no-taint baseline; solver reaches fixed point on the full gateway in < 1 s.

### M3 — `belay-eval`: corpus and metrics — **before any prompt work**
40–60 RustSec advisories mapped onto the taxonomy, vulnerable and patched tags both checked out. Metrics: detection, localization (span ∩ patch hunk), FP rate measured **on the patched tag** (same class + same file = confirmed FP, no hand labeling), discard rate, tokens/KLOC, cache hit rate. Paired bootstrap CI.
**Verify:** metrics reproducible to ±0 on a repeated run; the harness detects a deliberately broken prompt as a regression outside the CI.

### M4 — `belay-engine` pass 1 + verification
Frozen prefix, xgrammar-constrained candidate schema, span verification against file bytes, discard-on-mismatch.
**Verify:** discard rate < 5% on the corpus; recorded baseline detection/FP numbers; determinism — two runs produce byte-identical fingerprint sets.

**M4 is the real checkpoint.** Refutation only removes findings. If pass 1 + verification cannot find planted bugs, nothing downstream saves it.

### M5 — `belay-plan`: trie, order, partition, budget
Prompt trie, DFS emission order, greedy balanced tree partition, CELF budget solver, Belady hint stream.
**Verify:** measured cache hit rate ≥ 0.9 on a full scan; total prefill within 15% of the trie-node lower bound; planning time < 20 ms for 300 chains; scan order stable across runs.

### M6 — `belay-engine` pass 2: agentic refutation
Append-only history, 5 tools, constrained tool calls, e-process accumulator with SPRT-shaped thresholds, adaptive-submodular next-question hints, Weitzman ordering over candidates.
**Verify:** FP rate down measurably vs M4 on the same corpus with non-overlapping bootstrap CIs; mean turns < 5; hard ceiling of 16 hit in < 2% of rollouts.

### M7 — `belay-stat`: calibration, FDR, dedup, fingerprints
Platt+isotonic, ECE reporting, e-BH, LORD++ wealth persistence, MinHash/LSH clustering, FastCDC fingerprints, baseline.
**Verify:** ECE < 0.05 on held-out corpus; empirical FDR on the patched-tag runs ≤ nominal `q`; second run on unchanged code reports zero new findings; a whole-file reformat changes zero fingerprints.

### M8 — `belay-tui`: the session
`ratatui`, ArcSwap render loop, streaming, slash commands, inbox with Gcµ ordering, `/why` traces, `/cost`.
**Verify:** keystroke→render p99 < 16 ms under a running scan; first token p99 < 250 ms with a warm prefix; `/why` renders with zero inference calls.

### M9 — `/watch` + incrementality
salsa wiring, notify debounce, dirty-set closure, token-bucket budget, speculative prefetch.
**Verify:** single-file save → reindex < 50 ms; edit that makes a pre-existing pattern newly reachable **is** rescanned (the test a diff-scanner fails); prefetch hit rate reported and > 30% or auto-disabled.

### M10 — CI, SARIF, hardening
SARIF 2.1.0 export, `--fail-on`, exit codes, GitHub code-scanning ingest, `--ci` NP operating point, graceful shutdown flushing session + wealth state.
**Verify:** SARIF validates and renders in the GitHub UI; a seeded vuln in a PR fails the check; SIGTERM loses no findings and no alpha-wealth.

### M11 — MIR track (optional, gated on the M0 macro inventory)
`stable_mir` driver behind the same index trait, used by `/scan --deep` and CI.
**Verify:** on the corpus, deep mode strictly dominates `syn` mode on detection with no new FPs; if it doesn't, don't ship it.

---

# Part VIII — Crate Map & References

## Crate cheat-sheet

`tokio` · `ratatui` · `crossterm` · `syn` · `proc-macro2` · `rayon` · `salsa` · `lasso` · `rustc-hash` · `fixedbitset` · `roaring` · `bumpalo` · `arc-swap` · `ignore` · `notify` · `reqwest` · `serde` · `simd-json` · `blake3` · `redb` · `clap` · `mimalloc` · `hdrhistogram` · `tracing`

**Hand-rolled in-house** (all small, none worth a dependency): Tarjan SCC + condensation, 2-hop labels/PLL, bit-parallel BFS, Hopcroft–Karp, `MonotoneSolver<L>` + IFDS, Steensgaard union-find, prompt trie + DFS emitter, balanced tree partition, CELF lazy greedy, Weitzman reservation values, e-process/SPRT accumulator, Platt + PAVA isotonic, BH/e-BH/LORD++, MinHash + LSH banding, FastCDC, Gcµ inbox scheduler. Roughly 2,500 LOC total for the entire math layer.

## References

**Static analysis**
- **IFDS:** Reps, Horwitz & Sagiv, *Precise Interprocedural Dataflow Analysis via Graph Reachability* (POPL 1995). **IDE:** Sagiv, Reps & Horwitz (1996).
- **Dataflow / MFP:** Kildall (1973); Kam & Ullman (1977). **Fixed points:** Tarski (1955).
- **Pointer analysis:** Steensgaard (POPL 1996); Andersen (1994).
- **SCC:** Tarjan (1972). **2-hop labels:** Cohen, Halperin, Kaplan & Zwick (2003); **PLL:** Akiba, Iwata & Yoshida (SIGMOD 2013).
- **Path cover:** Dilworth (1950); König; **matching:** Hopcroft & Karp (1973).
- **Incremental:** Acar, *Self-Adjusting Computation* (2005); `salsa` / rust-analyzer.
- **Rust-specific prior art:** MIRAI (abstract interpretation over MIR); Rudra (Bae et al., SOSP 2021).

**Scheduling & caching**
- **Belady MIN:** Belady (1966). **General caching NP-hardness + Landlord:** Young (1994, 2002).
- **Submodular knapsack:** Nemhauser, Wolsey & Fisher (1978); Sviridenko (2004); **CELF:** Leskovec et al. (KDD 2007).
- **Adaptive submodularity:** Golovin & Krause (JAIR 2011).
- **Pandora's box:** Weitzman (Econometrica 1979).
- **List scheduling:** Graham (1969). **Power-of-two:** Mitzenmacher (2001).
- **Queueing:** Little (1961); Kingman (1961). **c-µ / Gcµ:** Cox & Smith (1961); Van Mieghem (1995).
- **Tail latency:** Dean & Barroso, *The Tail at Scale* (CACM 2013).

**Statistics & decision**
- **SPRT:** Wald (1945); optimality — Wald & Wolfowitz (1948).
- **E-values / anytime validity:** Ville (1939); Ramdas, Grünwald, Vovk & Shafer (2023).
- **Neyman–Pearson:** Neyman & Pearson (1933).
- **FDR:** Benjamini & Hochberg (1995); Benjamini & Yekutieli (2001); Storey (2002); **e-BH:** Wang & Ramdas (2022).
- **Online FDR:** Foster & Stine, *alpha-investing* (2008); Javanmard & Montanari, *LORD* (2018).
- **Conformal:** Vovk, Gammerman & Shafer (2005); Angelopoulos & Bates (2021); **risk control:** Angelopoulos et al. (2022).
- **Calibration:** Platt (1999); Zadrozny & Elkan (2002); **ECE:** Guo et al. (2017).
- **MinHash / LSH:** Broder (1997); Indyk & Motwani (1998).
- **CDC:** Rabin (1981); Xia et al., *FastCDC* (ATC 2016).
- **Bandits for tuning:** Jamieson & Talwalkar (2016); Li et al., *Hyperband* (2017).
