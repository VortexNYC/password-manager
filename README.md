# password-manager

Agent-first credential broker. Agents reference an item. Something outside the model injects the secret. The model never holds it.

Open source under Vortex NYC. Not a 1Password clone and not an auth company.

## What this is

Two principals (human, agent). Two grant levels:

- **Level 1** — agent does the work; a human does the last unlock.
- **Level 2** — this identity was donated to agents (service accounts, CI, a mailbox the bots own).

Same protocol on a laptop and in Codex Cloud / Flue / Cloudflare Agents. Org-ready from day one: an agent is owned by a user or by an org.

## Status

Engine only. Covered by tests. CLI/MCP/proxy are next.

```
make test
go run ./cmd/password-manager version
```

See [docs/SPEC.md](docs/SPEC.md) for the capability map and [docs/prior-art.md](docs/prior-art.md) for what we take from Infisical, Bitwarden, OneCLI, 1Password, Aside, Entra, and MeowPass.

## License

MIT. Copyright 2026 Vortex NYC, Inc.
