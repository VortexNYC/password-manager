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
| `LOADTEST_ORIGIN_MODE` | `goroutine` | `goroutine` (in-process), `process` (child `password-manager mcp` replicas), or `external` (URLs in `LOADTEST_ORIGINS`) |
| `LOADTEST_ORIGIN_BINARY` | auto | path to the `password-manager` binary for `process` mode; auto-built if unset |
| `LOADTEST_ORIGINS` | `""` | comma-separated external origin URLs for `external` mode |
| `LOADTEST_PROXY` | `1` for `goroutine`, `0` otherwise | use the local round-robin `httputil.ReverseProxy` |
| `LOADTEST_UPSTREAM_URL` | `""` | externally reachable upstream; a local `/ok` server is started if unset |
| `LOADTEST_RESET_DB` | `0` | when `1`, truncates load-test tables before seeding (destructive; test DB only) |
| `LOADTEST_REPLICAS` | 1 | origin replica count |
| `VEIL_VUS` | 50 | k6 virtual users |
| `VEIL_AUDIT_FLUSH_INTERVAL` | 5ms | max delay before an audit batch is flushed |
| `VEIL_MASTER_KEY` | generated if unset | 64-hex master key for the origin; generated when empty. Required for `external` mode and must match the key used by the external origins. |
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
| `agents` (session resolution + final reload) | 1,670,454 | 0.0141 | 23,506.0 | 2 |
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

### 5. Direct-origin geometry + consolidated session resolution

Code changes:

- `cmd/loadtest` can bypass the local `httputil.ReverseProxy` with
  `LOADTEST_PROXY=0`. k6 is then passed a comma-separated `VEIL_ORIGINS` list
  containing every replica URL and distributes requests across them.
- `internal/publicapi/api.go` adds a `/v1/use` fast path for session tokens:
  `AgentFromSession` resolves the token hash to the session's `agent_id` without
  loading the agent. `Broker.Use` then performs the authoritative `UseAuth`
  snapshot and the final agent reload before secret access.
- `PrincipalFromSession` still resolves the agent for endpoints that need the
  full principal; only `/v1/use` skips the session-side agent lookup.

With 3 replicas, 150 VUs, `VEIL_AUDIT_FLUSH_INTERVAL=20ms`, and a fresh loadtest
DB:

| Run | Proxy | Requests | Throughput | avg | p95 | max |
|---|---|---|---|---|---|---|
| `3rep-20ms-proxy-session` | yes | 800,260 | 6,669.1 req/s | 10.07 ms | 29.02 ms | 3.03 s |
| `3rep-20ms-direct-session` | no | 1,046,804 | 8,724.5 req/s | 7.69 ms | 22.64 ms | 1.65 s |

Direct-origin vs. proxied: **+30.9% throughput**, **-23.6% avg latency**,
**-22.0% p95 latency**. This is the same workload and the same Mac; the only
difference is removing the `httputil.ReverseProxy` hop.

Hot-path DB queries (`3rep-20ms-direct-session`):

| Query | Calls | Mean (ms) | Total (ms) | /request |
|---|---|---|---|---|
| `UseAuth` (LEFT JOIN of agents/items/grants/approvals) | 1,046,804 | 0.0339 | 35,465.1 | 1 |
| `sessions` (session resolution) | 1,046,804 | 0.0152 | 15,878.0 | 1 |
| `agents` (final reload before secret) | 1,046,804 | 0.0137 | 14,350.1 | 1 |
| `items` secret lookup | 1,046,804 | 0.0139 | 14,595.4 | 1 |
| `audit` COPY | 17,351 | 1.065 | 18,479.2 | 0.017 (batches) |

`agents` calls dropped from 2 per request (post-`UseAuth` consolidated) to 1.
Per `Use`, the origin now performs exactly 4 synchronous DB round trips
(`sessions`, `UseAuth`, final `agents`, `items` secret) plus an async audit
`COPY`.

pprof (`3rep-20ms-direct-session` CPU) is still dominated by network/runtime
wait states (`syscall.rawsyscalln` ~50%, runtime waits ~30%), confirming the
database is not the primary limiter even when the proxy is removed.

### 6. Session-aware `UseAuth` join

Code changes:

- `Store.UseAuthSession` resolves a session by secret hash and joins the
  authorization decision (`sessions` → `agents` → `items` → `grants` →
  `approvals`) in a single query for Postgres. Memory and SQLite resolve the
  session and reuse the existing `UseAuth` path.
- `Broker.UseSession` calls `Store.UseAuthSession`, then performs the final
  `Store.Agent` reload and the rest of the `Use` flow.
- `App.UseFetchSession` hashes the session token and calls `Broker.UseSession`.
- `internal/publicapi/api.go` routes session-token `POST /v1/use` directly to
  `App.UseFetchSession`; OIDC tokens still use `App.UseFetch`.

With 3 replicas, 150 VUs, `VEIL_AUDIT_FLUSH_INTERVAL=20ms`, direct origin, and a
fresh loadtest DB:

- Requests: **1,392,393**
- Throughput: **11,603.3 req/s** (+33.0% vs the prior 8,724.5 req/s direct run)
- Latency: avg **5.77 ms**, med **2.33 ms**, p95 **16.12 ms**, max **804.5 ms**
- Errors: **0%**
- Cache hit ratio: **0.9995**
- No waiting/blocked connections or deadlocks

Hot-path DB queries (`3rep-20ms-direct-useauthsession`):

| Query | Calls | Mean (ms) | Total (ms) | /request |
|---|---|---|---|---|
| `UseAuthSession` (LEFT JOIN sessions/agents/items/grants/approvals) | 1,392,393 | 0.044 | 61,255.7 | 1 |
| `items` secret lookup | 1,392,393 | 0.0149 | 20,781.1 | 1 |
| `agents` final reload | 1,392,393 | 0.0146 | 20,339.6 | 1 |
| `audit` COPY | 22,484 | 0.9084 | 20,425.5 | 0.016 (batches) |

The separate `sessions` lookup is gone. Per `Use` there are now **3**
synchronous DB round trips (`UseAuthSession`, final `agents`, `items` secret)
plus an async audit `COPY`.

## Interpretation

1. **Authorization read consolidation worked.** `UseAuth` collapsed the
   previously separate `agents`, `items`, `grants`, and `approvals` lookups into
   a single query, and removing `App.UseFetch`'s redundant `Store.Agent` call
   cut `agents` lookups from 4 to 2 per request. The 3-replica 20ms result is
   6,960 req/s, a ~27.7% gain over the prior 5,449 req/s baseline.
2. **The database is not the primary limiter.** Hot-path DB queries still run in
   ~0.015–0.044 ms with a cache hit ratio near 1.0 and no waiting/blocked
   connections. Per `Use` there are now 3 synchronous DB round trips
   (`UseAuthSession`, final `agents`, `items` secret), plus an async audit
   `COPY`.
3. **The local reverse proxy was a real limiter in this test geometry.** Removing
   the `httputil.ReverseProxy` hop and running k6 directly against the origin
   replicas increased throughput by ~31% and lowered latency by ~23% in the same
   150-VU/20ms configuration. This is a single-Mac measurement and not a
   production capacity claim, but it confirms the proxy was adding measurable
   overhead to the loopback path.
4. **Session-resolution consolidation worked.** Resolving only `sessions.agent_id`
   in `/v1/use` and letting `Broker.Use`/`UseAuth` own the authoritative agent
   snapshot dropped `agents` lookups from 2 to 1 per request. Fail-closed
   revocation behavior is preserved by the final `Store.Agent` reload before
   secret access.
5. **The remaining time is still local network/runtime overhead.** The pprof CPU
   profile for the direct-origin run shows the majority of samples in
   `syscall.rawsyscalln` and runtime wait states. This is loopback I/O and Go
   runtime scheduling between k6, the origins, and the upstream test server, not
   DB work or JSON/crypto/scrub.
6. **Run-to-run variance is high on a single Mac.** Identical 3-replica 20ms
   runs varied from ~5.2k to ~8.7k req/s depending on proxy and distribution.
   The DB metrics are stable, so the variance is in the local network stack and
   k6 scheduling. Treat the numbers as directional, not a capacity guarantee.
7. **A 20ms audit flush still outperforms 5ms.** The clean 20ms direct-origin run
   was ~8,724 req/s vs ~6,669 req/s for the proxied 20ms run and ~5,248 req/s
   for the consolidated `UseAuth` 5ms run. Larger audit batches reduce `COPY`
   overhead.
8. **Session-aware `UseAuth` is the next big win.** Joining `sessions` into the
   `UseAuth` snapshot removed the standalone `sessions` call and cut the hot
   path to 3 DB round trips. Throughput rose from 8,724 req/s to 11,603 req/s
   (+33%) and p95 fell from 22.64 ms to 16.12 ms (-29%) in the same
   150-VU/20ms direct-origin configuration. Fail-closed behavior is preserved:
   `UseAuthSession` returns `ErrNotFound` for missing or expired sessions, and
   the final `Store.Agent` reload still guards against revocation races.

## Decisions

| Decision | Status | Rationale |
|---|---|---|
| Async audit with bounded flush | **Kept** | Improves throughput and tail latency; crash-loss window is explicit and acceptable. |
| `VEIL_AUDIT_FLUSH_INTERVAL=5ms` default | **Kept** | 20ms is faster in this workload, but 5ms keeps the in-memory audit window smaller; deployments can override per risk/cost appetite. |
| Per-request `slog.Info` in benchmark | **Suppressed in harness** | Avoids log I/O distorting results; production can enable INFO. |
| `Store.UseAuth` consolidation | **Kept** | Cuts DB round trips and raises throughput; fail-closed final agent reload is preserved. |
| Remove `App.UseFetch` pre-call | **Kept** | The broker already reloads the agent; the extra `Store.Agent` was pure overhead. |
| Add pprof to harness | **Kept** | Confirms the remaining time is network/runtime, not DB. |
| Bypass `httputil.ReverseProxy` in load-test geometry | **Kept** | Separates proxy overhead from origin capacity; shows a meaningful gain in this harness. |
| `UseAuthSession` join for session-token `/v1/use` | **Kept** | Removes the standalone `sessions` lookup and the intermediate `AgentFromSession` step; fail-closed revocation race guard is preserved. |
| `mcp` command respects `VEIL_LOG_LEVEL` | **Kept** | Prevents child-process origins from emitting per-request `slog.Info("use")` logs that become the measured limiter. |

### 7. Multi-process origin mode

Code changes:

- `cmd/loadtest` supports `LOADTEST_ORIGIN_MODE=process` to start the Veil
  binary as child `mcp` processes on ephemeral ports, simulating separate
  Railway-like origin replicas against the same Postgres.
- `LOADTEST_ORIGIN_BINARY` lets the harness use a pre-built binary; otherwise it
  builds a temporary `password-manager` binary.
- `internal/cli/cli.go` (`mcp` command) now honors `VEIL_LOG_LEVEL`, so child
  origins can suppress per-request INFO logs during benchmarks.
- The harness seeds from a short-lived Postgres app, truncates load-test tables
  when `LOADTEST_RESET_DB=1`, and passes the seeded token/item to `k6`.

With 3 child-process replicas, 150 VUs,
`VEIL_AUDIT_FLUSH_INTERVAL=20ms`, `LOADTEST_PROXY=0` (direct origin), and
`VEIL_MAX_IN_FLIGHT_USE=300`:

| Metric | Value |
|---|---|
| Requests | 52,200 |
| Throughput | 434.99 req/s |
| Latency avg / med / p95 / max | 155.83 ms / 25.76 ms / 810.41 ms / 4,475.12 ms |
| Errors | 0% |
| Cache hit ratio | 1.0 |
| Deadlocks / waiting connections | 0 |

Hot-path DB queries (`pgbot-after`):

| Query | Calls | Mean (ms) | Total (ms) |
|---|---|---|---|
| `ConsumeSession` (`UPDATE sessions SET uses = uses + 1 FROM agents ...`) | 52,200 | **91.70** | **4,786,852.11** |
| `UseAuthSession` (LEFT JOIN `sessions → agents → items → grants → approvals`) | 52,200 | 0.0574 | 2,998.57 |
| `audit` COPY | 7,317 | 0.1429 | 1,045.68 |
| `items` secret lookup | 52,200 | 0.0102 | 534.18 |
| `agents` final reload | 52,200 | omitted | small |

Interpretation of this run:

- The **single shared session across all VUs creates a row-lock hot spot**.
  Every `Use` updates the same `sessions` row (`uses = uses + 1`), so the
  session row serializes 150 concurrent VUs. The `ConsumeSession` query averages
  91.7 ms and accounts for almost all DB time. This is a load-test artifact,
  not a realistic production pattern: real agents/sessions are distributed
  across many rows and lock contention is per-session, not global.
- `UseAuthSession` itself is still fast (~0.06 ms) and the hot path remains 3
  synchronous DB round trips plus an async audit `COPY`.
- Process overhead is visible but secondary to the session-row lock: the
  in-process `UseAuthSession` run achieved 11,603 req/s on the same workload,
  while the child-process run achieved 435 req/s because every origin process
  contends for the same session row.

## Next optimization

The hot path is now 3 synchronous DB round trips per `Use` (`UseAuthSession`,
final `agents`, `items` secret) plus an async audit `COPY`. The `UseAuthSession`
read itself is fast (~0.06 ms), and fail-closed revocation is preserved by the
final `agents` reload before secret access.

Before adding a fail-closed cache or distributed rate limiting:

1. **Get a true multi-process capacity number.** The first `process`-mode run
   was dominated by a single shared session row: `ConsumeSession` averaged 91.7
   ms because 150 VUs were all updating the same `sessions` row. The harness
   should seed multiple sessions and distribute tokens across VUs, or use
   `max_uses` and renew logic, so the measurement reflects per-session lock
   contention rather than a single-row hot spot.
2. **Move the final `agents` reload into `UseAuthSession` if it can be done
   safely.** The final reload is the revocation race guard. If we can express
   `UseAuthSession` as a single snapshot that is still authoritative at the
   moment we read the secret, we could remove the extra `agents` call and cut
   the hot path to 2 round trips. This is the highest remaining DB-side win once
   the session-row artifact is removed from the measurement.
3. **Run a multi-host load test.** Single-Mac loopback variance and child-process
   scheduling noise are still clouding the numbers. A `k6` runner on a separate
   core or host with the origin and Postgres on other machines will separate
   test-stack overhead from real origin capacity.
4. **Only after the hot path is flat and measured away from loopback, consider a
   short-lived, fail-closed cache** for session/grant metadata with explicit
   invalidation and distributed rate limiting.

