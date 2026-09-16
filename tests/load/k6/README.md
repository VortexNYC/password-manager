# Veil load tests (k6)

These scripts measure the origin hot path. They are designed to run against a
real deployment or a multi-replica local origin backed by Postgres, not the
single-node SQLite development vault.

## Setup

1. Deploy or start the origin with `VEIL_POSTGRES_DSN` and `VEIL_MASTER_KEY`.
2. Create a human, an item, an agent, and a grant that allows `fetch` on that
   item. The public API has `POST /v1/items`, `/v1/agents`, `/v1/grants`.
3. Create a session for the agent via `POST /v1/sessions` and capture the
   `token`.
4. Optionally set `VEIL_UPSTREAM_URL` to a stable echo endpoint that the
   origin can proxy. The default is `https://httpbin.org/get`.

## Run

```bash
VEIL_ORIGIN=https://veil.nyc \
VEIL_AGENT_TOKEN=<session-token> \
VEIL_ITEM_ID=<item-id> \
k6 run tests/load/k6/use.js
```

## What it proves

The script ramps virtual users, calls `POST /v1/use`, and checks that the
authorization decision is `allow`. Use it to validate that the origin stays
under latency thresholds as replicas and Postgres connections are scaled.
