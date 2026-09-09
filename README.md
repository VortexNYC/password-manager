# password-manager

Agent-first credential broker. Agents reference an item. Something outside the model injects the secret. The model never holds it.

Open source under Vortex NYC. Not a 1Password clone and not an auth company.

## What this is

Two principals (human, agent). Two grant levels:

- **Level 1** — agent does the work; a human does the last unlock.
- **Level 2** — this identity was donated to agents (service accounts, CI, a mailbox the bots own).

Same protocol on a laptop and in Codex Cloud / Flue / Cloudflare Agents. Org-ready from day one: an agent is owned by a user or by an org.

## Status

Engine + local SQLite vault + CLI + MCP. Covered by tests.

```
make test
go run ./cmd/password-manager init --home /tmp/pwm
go run ./cmd/password-manager item add stripe --home /tmp/pwm --uri https://api.stripe.com --secret-file ./key
go run ./cmd/password-manager agent add claude --home /tmp/pwm
go run ./cmd/password-manager grant add --home /tmp/pwm --agent claude --item stripe --level level2
PWM_AGENT=claude go run ./cmd/password-manager mcp --home /tmp/pwm
go run ./cmd/password-manager run --home /tmp/pwm --agent claude -- curl -s https://api.stripe.com/v1/customers
```

MCP tools: `list_items`, `fetch`. Bound to `PWM_AGENT`. The model cannot switch principals. Secrets never appear in tool output.

`run` / `proxy` is the Infisical path: unmodified HTTP clients go through `HTTPS_PROXY`. Unknown hosts fail closed. A per-vault CA (`ca.pem`) is used for MITM — not goproxy's public default.

There is no `item get`. Secrets are injected at Use, not printed.

See [docs/SPEC.md](docs/SPEC.md) for the capability map and [docs/prior-art.md](docs/prior-art.md) for what we take from Infisical, Bitwarden, OneCLI, 1Password, Aside, Entra, and MeowPass.

## License

MIT. Copyright 2026 Vortex NYC, Inc.
