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

- Requests: **563,665**
- Throughput: **4,697.2 req/s**
- Latency: avg **4.72 ms**, med **4.56 ms**, p95 **8.44 ms**, max **22.27 ms**
- Errors: **0%**
- Postgres connections: **24** (20 origin pool + observer overhead)
- Cache hit ratio: **1.0**
- Deadlocks: **0**
- Top DB work by `total_ms`:
  - `agents` lookup: 2,254,663 calls, 24,752 ms (4 per request)
  - audit `COPY`: 15,978 calls, 4,696 ms, 563,665 rows (~35 rows/COPY)
  - `items` metadata lookup: 563,666 calls, 7,051 ms
  - `sessions` lookup: 563,665 calls, 6,855 ms
  - `grants` lookup: 563,665 calls, 6,865 ms
  - `items` secret lookup: 563,665 calls, 6,508 ms
  - `approvals` lookup: 563,665 calls, 5,457 ms

### 2. Multi-replica: 3 replicas, `VEIL_AUDIT_FLUSH_INTERVAL=5ms`

- Requests: **607,068**
- Throughput: **5,058.9 req/s**
- Latency: avg **13.29 ms**, med **4.83 ms**, p95 **38.75 ms**, max **1.1 s**
- Errors: **0%**
- Postgres connections: **64** (20 per replica + observer overhead)
- Cache hit ratio: **1.0**
- Deadlocks: **0**
- Top DB work by `total_ms`:
  - `agents` lookup: 2,428,275 calls, 28,734 ms (4 per request)
  - audit `COPY`: 35,336 calls, 11,893 ms, 606,468 rows (~17 rows/COPY)
  - `items` metadata lookup: 607,069 calls, 8,022 ms
  - `sessions` lookup: 607,068 calls, 7,920 ms
  - `grants` lookup: 607,068 calls, 7,810 ms
  - `items` secret lookup: 607,068 calls, 7,451 ms
  - `approvals` lookup: 607,068 calls, ~6,300 ms

### 3. Multi-replica: 3 replicas, `VEIL_AUDIT_FLUSH_INTERVAL=20ms`

- Requests: **648,180**
- Throughput: **5,401.5 req/s** (+6.8% vs 5ms)
- Latency: avg **12.44 ms**, med **4.59 ms**, p95 **40.80 ms**, max **1.2 s**
- Errors: **0%**
- Postgres connections: **64**
- Cache hit ratio: **1.0**
- Deadlocks: **0**
- Top DB work by `total_ms`:
  - `agents` lookup: 2,592,723 calls, 30,010 ms (4 per request)
  - audit `COPY`: 15,175 calls, 10,170 ms, 648,180 rows (~43 rows/COPY)
  - `items` metadata lookup: 648,181 calls, 8,385 ms
  - `sessions` lookup: 648,180 calls, 8,357 ms
  - `grants` lookup: 648,180 calls, 8,164 ms
  - `items` secret lookup: 648,180 calls, 7,784 ms
  - `approvals` lookup: 648,180 calls, 6,483 ms

## Interpretation

1. **Audit batching is effective.** Moving `AppendAudit` off the synchronous path
   and flushing in batches removed the per-request audit INSERT from the hot
   path. At 5ms the `COPY` batch size is ~17 rows; at 20ms it is ~43 rows.
   20ms raises throughput by ~6.8% (5,401 vs 5,058 req/s) but also increases
   p95 (40.8 ms vs 38.75 ms) and the largest single `COPY` spike (600 ms vs
   245 ms), so 5ms remains the safer default.
2. **The database is not the primary limiter.** Each hot-path query executes in
   ~0.012 ms and the cache hit ratio is 1.0. Even with 3 replicas the Postgres
   connections are idle most of the time (`active: 0` at the snapshot), and
   `total_exec_ms` is low relative to wall time.
3. **Multi-replica scaling is sub-linear.** 1 replica reaches ~4.7k req/s;
   3 replicas reach ~5.1k req/s, not ~14k. The shared Postgres instance is not
   saturated, so the bottleneck is elsewhere: the local proxy, the sequential
   per-request round trips, or the synchronous upstream fetch/scrub work.
4. **The `agents` query dominates `total_exec_ms`.** It is executed 4 times per
   `Use` request. Consolidating the authorization pre-checks into fewer round
   trips is the next obvious DB-side improvement.

## Decisions

| Decision | Status | Rationale |
|---|---|---|
| Async audit with bounded flush | **Kept** | Improves throughput and tail latency; crash-loss window is explicit and acceptable. |
| `VEIL_AUDIT_FLUSH_INTERVAL=5ms` default | **Kept** | 20ms slightly increases batch size but adds durability exposure; tune per deployment. |
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

