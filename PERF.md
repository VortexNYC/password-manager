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
- `pg_stat_statements` is enabled and reset before each run.
- Origin replicas are stopped and their async auditors are closed before the
final pgbot snapshot, so `pg_stat_statements` includes every audit `COPY`.
- pgbot snapshots are captured after each run with
`pgbot inspect --format json --fail-on none`.

## Environment variables

| Variable | Default | Purpose |
|---|---|---|
| `PG_TEST_DSN` | required | Postgres DSN for the harness |
| `LOADTEST_REPLICAS` | 1 | origin replica count |
| `VEIL_VUS` | 50 | k6 virtual users |
| `VEIL_AUDIT_FLUSH_INTERVAL` | 5ms | max delay before an audit batch is flushed |
| `VEIL_MASTER_KEY` | generated if unset | 64-hex master key for the origin; generated when empty |
| `VEIL_LOG_LEVEL` | warn | suppress per-request INFO logs during benchmarks |

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

## Interpretation

1. **Audit batching is effective.** Moving `AppendAudit` off the synchronous path
   and flushing in batches removed the per-request audit INSERT from the hot
   path. At 5ms the three-replica `COPY` batch size is ~16 rows; at 20ms it is
   ~43 rows. 20ms raises three-replica throughput by ~4.0% (5,449 vs 5,238 req/s)
   and cuts total `COPY` time by ~31% (8.7s vs 12.6s). The p95s are comparable
   (38.15 ms vs 38.31 ms), so the larger flush interval is a measurable win for
   write-heavy load at the cost of a slightly larger in-memory durability window.
2. **The database is not the primary limiter.** Each hot-path query executes in
   ~0.012 ms and the cache hit ratio is 1.0. `pg_stat_activity` shows no waiting,
   blocked, or idle-in-transaction connections, and `total_exec_ms` is low relative
   to wall time.
3. **Multi-replica scaling is sub-linear.** 1 replica reaches ~4.8k req/s;
   3 replicas reach ~5.2k req/s, not ~14k. The shared Postgres instance is not
   saturated, so the bottleneck is elsewhere: the local proxy, the sequential
   per-request round trips, or the synchronous upstream fetch/scrub work.
4. **The `agents` query dominates `total_exec_ms`.** It is executed 4 times per
   `Use` request. Consolidating the authorization pre-checks into fewer round
   trips is the next obvious DB-side improvement.

## Decisions

| Decision | Status | Rationale |
|---|---|---|
| Async audit with bounded flush | **Kept** | Improves throughput and tail latency; crash-loss window is explicit and acceptable. |
| `VEIL_AUDIT_FLUSH_INTERVAL=5ms` default | **Kept** | 20ms is a measurable throughput/win for this workload, but 5ms keeps the in-memory audit window smaller; deployments can override per risk/cost appetite. |
| Per-request `slog.Info` in benchmark | **Suppressed in harness** | Avoids log I/O distorting results; production can enable INFO. |

## Next optimization

The next foundational slice should measure and reduce the non-DB work on the
`Use` hot path. Specifically:

1. Add CPU profiling to the load harness (`runtime/pprof`) so the next baseline
   identifies whether the limiter is the proxy, JSON/cryptographic work, the
   upstream fetch, or the response scrub.
2. Consolidate the repeated `agents` lookups and the `items` metadata/secret
   lookups into a single authorization query where possible, because `pg_stat`
   shows those are the largest DB consumers even though they are individually
   fast.
3. Only after the hot path is flat consider a short-lived, fail-closed cache
   with explicit invalidation; cache is premature until the round-trip count is
   minimized.

