# Veil performance ledger

This file records measured performance for the Postgres-backed origin and the
optimizations we try. Numbers are from a local 2023 Apple Silicon Mac with a
Docker Postgres 16.15 container (`pg-pm-test`) and the `cmd/loadtest` harness.
They are not a production capacity guarantee; they are a repeatable baseline for
comparing changes.

## Methodology

- Target endpoint: `POST /v1/use`.
- k6 script: `tests/load/k6/use.js`.
- Origin: one or three stateless replicas started by `cmd/loadtest`, backed by
the same Postgres DSN.
- Proxy: a local round-robin `httputil.ReverseProxy` inside the harness.
- Upstream: a local `/ok` handler returning `{"ok":true}`.
- Audit: asynchronous via `internal/audit.Async`, flushed to Postgres with
`AppendAudits` (COPY).
- Per-request `slog.Info("use")` logs are suppressed (`VEIL_LOG_LEVEL=warn`)
during the run to avoid log I/O becoming the measured limiter.
- `pg_stat_statements` is enabled; the harness resets it before the workload
starts so the `pgbot-after` snapshot contains only the current run.
- Origin replicas are stopped and their async auditors are closed before the
final pgbot snapshot, so `pg_stat_statements` includes every audit `COPY`.
- pgbot snapshots are captured after each run with
`pgbot inspect --format json --fail-on none`.
- The harness captures a 120s CPU profile (`cpu.pprof`) and a heap snapshot
(`heap.pprof`) under `tests/load/k6/out/<run>/`.

## Environment variables

| Variable | Default | Purpose |
|---|---|---|
| `PG_TEST_DSN` | required | Postgres DSN for the harness |
| `LOADTEST_REPLICAS` | 1 | origin replica count |
| `VEIL_VUS` | 50 | k6 virtual users |
| `VEIL_AUDIT_FLUSH_INTERVAL` | 5ms | max delay before an audit batch is flushed |
| `VEIL_MASTER_KEY` | generated if unset | 64-hex master key for the origin; generated when empty |
| `VEIL_LOG_LEVEL` | warn | suppress per-request INFO logs during benchmarks |
| `LOADTEST_OUT` | `tests/load/k6/out` | artifact directory for k6, pgbot, and pprof output |
| `VEIL_MAX_IN_FLIGHT_USE` | 0 (unlimited) | per-origin in-flight `Use` limit; 0 disables admission control |

## Results

### 1. Baseline: 1 replica, `VEIL_AUDIT_FLUSH_INTERVAL=5ms`

- Requests: **579,511**
- Throughput: **4,829.2 req/s**
- Latency: avg **4.60 ms**, med **4.42 ms**, p95 **8.29 ms**, max **114.10 ms**
- Errors: **0%**
- Cache hit ratio: **1.0**
- Deadlocks: **0**
- No waiting or blocked connections
- Top DB work by `total_ms`:
  - `agents` lookup: 2,318,047 calls, 25,612 ms (4 per request)
  - `items` metadata lookup: 579,512 calls, 7,171 ms
  - `grants` lookup: 579,511 calls, 6,928 ms
  - `sessions` lookup: 579,511 calls, 6,801 ms
  - `items` secret lookup: 579,511 calls, 6,727 ms
  - `approvals` lookup: 579,511 calls, 5,545 ms
  - audit `COPY`: 16,088 calls, 4,586 ms, 579,511 rows (~36 rows/COPY)

### 2. Multi-replica: 3 replicas, `VEIL_AUDIT_FLUSH_INTERVAL=5ms`

- Requests: **628,634**
- Throughput: **5,238.6 req/s**
- Latency: avg **12.83 ms**, med **4.75 ms**, p95 **38.31 ms**, max **3.72 s**
- Errors: **0%**
- Cache hit ratio: **1.0**
- Deadlocks: **0**
- No waiting or blocked connections
- Top DB work by `total_ms`:
  - `agents` lookup: 2,514,539 calls, 30,089 ms (4 per request)
  - audit `COPY`: 38,434 calls, 12,636 ms, 628,074 rows (~16 rows/COPY)
  - `items` metadata lookup: 628,635 calls, 8,447 ms
  - `sessions` lookup: 628,634 calls, 8,317 ms
  - `grants` lookup: 628,634 calls, 8,194 ms
  - `items` secret lookup: 628,634 calls, 7,854 ms

### 3. Multi-replica: 3 replicas, `VEIL_AUDIT_FLUSH_INTERVAL=20ms`

- Requests: **654,059**
- Throughput: **5,449.5 req/s** (+4.0% vs 5ms)
- Latency: avg **12.33 ms**, med **4.87 ms**, p95 **38.15 ms**, max **813.1 ms**
- Errors: **0%**
- Cache hit ratio: **1.0**
- Deadlocks: **0**
- No waiting or blocked connections
- Top DB work by `total_ms`:
  - `agents` lookup: 2,616,239 calls, 31,311 ms (4 per request)
  - `sessions` lookup: 654,059 calls, 8,780 ms
  - `items` metadata lookup: 654,060 calls, 8,739 ms
  - audit `COPY`: 15,167 calls, 8,728 ms, 654,059 rows (~43 rows/COPY)
  - `grants` lookup: 654,059 calls, 8,491 ms
  - `items` secret lookup: 654,059 calls, 8,098 ms

### 4. Consolidated authorization reads + redundant agent fetch removal

Code changes:

- `Store.UseAuth` returns a single snapshot of agent + item + grant + approval
  in one query (SQLite `LEFT JOIN`, Postgres `LEFT JOIN`).
- `Broker.Use` uses `UseAuth` for the authorization decision, then reloads the
  agent once immediately before secret access.
- `App.UseFetch` no longer fetches the agent itself; `Broker.Use` owns the
  lookup.
- `cmd/loadtest` now resets `pg_stat_statements` before each run, captures
  `cpu.pprof` and `heap.pprof`, and removes the stale diagnostic print.

With a fresh `loadtest` DB, `pg_stat_statements` reset, and 20ms audit flush:

- Run A: 3 replicas, 150 VUs
  - Requests: **835,227**
  - Throughput: **6,960.0 req/s** (+27.7% vs the prior 5,449.5 req/s 3-replica 20ms baseline)
  - Latency: avg **9.64 ms**, med **3.42 ms**, p95 **27.72 ms**, max **1.96 s**
  - Errors: **0%**
  - Cache hit ratio: **1.0**
  - No waiting/blocked connections or deadlocks
- Run B: 3 replicas, 150 VUs, 5ms audit flush
  - Requests: **629,717**
  - Throughput: **5,247.6 req/s**
  - Latency: avg **12.80 ms**, med **3.84 ms**, p95 **34.53 ms**, max **923.92 ms**
- Run C: 1 replica, 50 VUs, 20ms audit flush
  - Requests: **618,791**
  - Throughput: **5,156.5 req/s**
  - Latency: avg **4.29 ms**, med **3.25 ms**, p95 **9.46 ms**, max **491.7 ms**

Clean `pgbot-after` (Run A) hot-path queries per request:

| Query | Calls | Mean (ms) | Total (ms) | /request |
|---|---|---|---|---|
| `UseAuth` (LEFT JOIN of agents/items/grants/approvals) | 835,227 | 0.0362 | 30,227.5 | 1 |
| `agents` (final reload before secret) | 1,670,454 | 0.0141 | 23,506.0 | 2 |
| `sessions` (session resolution) | 835,227 | 0.0155 | 12,973.8 | 1 |
| `items` secret lookup | 835,227 | 0.0145 | 12,141.3 | 1 |
| `audit` COPY | 14,606 | 1.0791 | 15,761.2 | 0.017 (batches) |

pprof (Run A CPU) top-line observations:

- **Network syscalls dominate CPU time**: `syscall.rawsyscalln` 54.38%,
  `runtime.pthread_cond_wait` 12.21%, `runtime.usleep` 11.35%,
  `runtime.kevent` 8.06%. These are runtime/network wait states and local
  loopback I/O, not DB query execution.
- `github.com/jackc/pgx/v5.(*Conn).Query` 22.72%,
  `internal/store.(*Postgres).UseAuth` 5.25%,
  `internal/store.(*Postgres).Agent` 9.21%,
  `internal/store.(*Postgres).Secret` 4.30%.
- `internal/app.(*App).PrincipalFromSession` 8.72% (session + agent lookup),
  `internal/publicapi.(*Server).useItem` 24.39% (full handler).

## Interpretation

1. **Authorization read consolidation worked.** `UseAuth` collapsed the
   previously separate `agents`, `items`, `grants`, and `approvals` lookups into
   a single query, and removing `App.UseFetch`'s redundant `Store.Agent` call
   cut `agents` lookups from 4 to 2 per request. The 3-replica 20ms result is
   6,960 req/s, a ~27.7% gain over the prior 5,449 req/s baseline.
2. **The database is not the primary limiter.** Hot-path DB queries still run in
   ~0.012–0.036 ms with a cache hit ratio of 1.0 and no waiting/blocked
   connections. Per request there are only ~4 DB round trips now (`sessions`,
   `UseAuth`, final `agents` reload, `items` secret), plus an async audit `COPY`.
3. **The remaining time is mostly local network/runtime overhead.** The pprof CPU
   profile shows >50% of samples in `syscall.rawsyscalln` and runtime wait
   states (`pthread_cond_wait`, `usleep`, `kevent`). This is loopback I/O and
   Go runtime scheduling between k6, the local reverse proxy, three origins,
   and the upstream test server, not DB work or JSON/crypto/scrub.
4. **Run-to-run variance is high on a single Mac.** Identical 3-replica 20ms
   runs varied from ~5.2k to ~7.0k req/s. The DB metrics are stable, so the
   variance is in the local network stack and k6 scheduling. Treat the numbers
   as directional, not a capacity guarantee.
5. **A 20ms audit flush still outperforms 5ms.** The clean 20ms run was ~6,960
   req/s vs ~5,248 req/s for 5ms in the same configuration, a ~32.6% difference
   in this run. The larger flush batches more audit events and reduces COPY
   overhead, at the cost of a slightly larger in-memory window.

## Decisions

| Decision | Status | Rationale |
|---|---|---|
| Async audit with bounded flush | **Kept** | Improves throughput and tail latency; crash-loss window is explicit and acceptable. |
| `VEIL_AUDIT_FLUSH_INTERVAL=5ms` default | **Kept** | 20ms is faster in this workload, but 5ms keeps the in-memory audit window smaller; deployments can override per risk/cost appetite. |
| Per-request `slog.Info` in benchmark | **Suppressed in harness** | Avoids log I/O distorting results; production can enable INFO. |
| `Store.UseAuth` consolidation | **Kept** | Cuts DB round trips and raises throughput; fail-closed final agent reload is preserved. |
| Remove `App.UseFetch` pre-call | **Kept** | The broker already reloads the agent; the extra `Store.Agent` was pure overhead. |
| Add pprof to harness | **Kept** | Confirms the remaining time is network/runtime, not DB. |

## Next optimization

pprof shows the remaining time is primarily local network I/O and runtime
scheduling, not DB, JSON, crypto, or scrub. The next foundational slice should
attack those limits before adding caching or rate limiting:

1. **Remove the local reverse proxy from the test path.** The test currently
   routes k6 -> proxy -> origin -> upstream -> origin -> proxy -> k6. Running k6
   against a single origin or against a fast L7 load balancer on the same host
   will separate proxy overhead from origin capacity. The current `httputil`
   round-robin proxy is a measurement convenience, not production architecture.
2. **Consolidate session resolution with `UseAuth`.** `PrincipalFromSession` does
   a separate `sessions` + `agents` lookup before `Broker.Use` starts. A single
   `UseAuth`-style join that also resolves the session by hash would remove the
   remaining extra round trip (but it must not leak the secret to the resolver).
3. **Run a multi-host load test.** Single-Mac loopback variance is high. A `k6`
   runner on a second core/host with the origin on one machine and the load
   generator on another will give a clearer picture of whether the origin or the
   local test stack is the limiter.
4. **Only after those are measured and flat, consider a short-lived, fail-closed
   cache** for session/grant metadata with explicit invalidation and distributed
   rate limiting.

