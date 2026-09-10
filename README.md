# Veil

Agent-first credential broker. Agents reference an item. Something outside the model injects the secret. The model never holds it.

The product is Veil. This repo and the CLI stay `password-manager` in the Vortex org for now.

Open source under Vortex NYC. Not a 1Password clone and not an auth company.

**Ory \*** — the identity vendor, not us. **Kratos** = humans (email, login, invite). **Hydra** = tokens. **Keto** = org owner/member. **Glue** talks to those three. **This repo** is the broker (secrets, grants, inject). Cheatsheet: `AGENTS.md` and `docs/SPEC.md`.

## What this is

Two principals (human, agent). Two grant levels:

- **Level 1** — agent does the work; a human does the last unlock.
- **Level 2** — this identity was donated to agents (service accounts, CI, a mailbox the bots own).

Same protocol on a laptop and in Codex Cloud / Flue / Cloudflare Agents. An agent is a principal. Cloud and laptop prove it with the same OIDC token we verify. The laptop socket is transport, not a second identity.

## Status

Engine + local SQLite vault + CLI + MCP. Covered by tests.

```
make test
go run ./cmd/password-manager init --home /tmp/pwm
go run ./cmd/password-manager item add stripe --home /tmp/pwm --uri https://api.stripe.com --secret-file ./key --totp-file ./seed
go run ./cmd/password-manager agent add claude --home /tmp/pwm
go run ./cmd/password-manager agent bind claude --home /tmp/pwm --issuer https://token.actions.githubusercontent.com --subject 'repo:vortexnyc/password-manager:ref:refs/heads/main' --audience password-manager
go run ./cmd/password-manager grant add --home /tmp/pwm --agent claude --item stripe --level level2
go run ./cmd/password-manager mcp --home /tmp/pwm
go run ./cmd/password-manager mcp config
go run ./cmd/password-manager serve --home /tmp/pwm
go run ./cmd/password-manager fill install --home /tmp/pwm
go run ./cmd/password-manager item add github --home /tmp/pwm --ssh-file ./id_ed25519
go run ./cmd/password-manager ssh --home /tmp/pwm
go run ./cmd/password-manager run --home /tmp/pwm --agent claude -- curl -s https://api.stripe.com/v1/customers
```

MCP tools: `list_items`, `fetch`. HTTP: `GET /v1/items`, `POST /v1/use`, `GET /v1/events`, owner `POST /v1/items` and `/v1/grants`. Same operations. Streamable HTTP MCP at `https://veil.nyc/mcp`. OpenAPI at `https://veil.nyc/openapi.json`. Bearer is the agent or a Keto member human (`PWM_OIDC_TOKEN` / Hydra JWT). `PWM_ORIGIN=https://veil.nyc` makes CLI `use`, `audit`, `item`, `grant`, and `fill` hit that API and never open a second sqlite. Cursor (Dock-launched, no Bearer interpolation) uses `password-manager mcp stdio` against that origin; token stays in `PWM_OIDC_TOKEN_FILE`. If that JWT is stale, stdio remints with `client_credentials` from `PWM_HYDRA_SECRET_FILE` (Hydra public issuer). The Hydra client secret never enters MCP JSON. The model cannot switch principals and never sees the token. Secrets never appear in tool or SDK output. SDKs are generated: `pnpm run sdk:generate`. Docs: `pnpm run docs:dev`.

Cloud agents (Flue, Cloudflare, Codex) hit the URL with Bearer. The host is not identity. Origin is Railway. Cloudflare DNS only. Cloud agents mint at `https://id.veil.nyc` (`client_credentials`), then send the JWT. Hydra admin stays private.

```
password-manager agent add cursor
password-manager agent hydra cursor --secret-file ./cursor.hydra
password-manager agent token cursor --secret-file ./cursor.hydra --out-file ./cursor.jwt
password-manager grant add --agent cursor --item stripe --level level2
password-manager mcp
password-manager mcp config
password-manager mcp laptop
```

Paste `mcp config` as the HTTP server block when the process has `PWM_OIDC_TOKEN`. Cursor does not: `password-manager mcp laptop` prints the stdio block with the token-file *path* that is already in the env, never the JWT, never `${file:}`. `mcp config` includes `issuer` when `PWM_HYDRA_ISSUER` is set (`https://id.veil.nyc`). `.well-known/oauth-protected-resource` points at that issuer. Mint: `agent token` (`POST {issuer}/oauth2/token`). The JWT is `--out-file` only.

`run` is Infisical `vault run`: granted item material is in the child's environment (item name → env var, uppercased). `HTTPS_PROXY` is still set for MITM. The broker does not print the secret. Level 1 is skipped until a human Approves. SSH keys stay on `ssh.sock`.

`run` / `proxy` MITM: unmodified HTTP clients go through `HTTPS_PROXY`. Unknown hosts fail closed. A per-vault CA (`ca.pem`) is used for MITM — not goproxy's public default.

`fill` is the native host (native messaging + nacl box). `password-manager fill install` registers this process. Slice 26 dogfoods store KeePassXC-Browser. Customers get a Veil-branded extension (SPEC slice 37). Fill writes into the page. Agents never receive the secret.

`ssh` is the OpenSSH agent. Export `SSH_AUTH_SOCK` from its output. The broker signs. The private key never leaves. `item add --ssh-file` stores the PEM; never argv.

`human invite EMAIL --code-file` is the Ory invite: Kratos creates the identity and a recovery code. Glue stamps `organization_id` and writes Keto owner/member. After the first human, invite requires an owner (`--oidc-token-file` / `PWM_HUMAN_TOKEN`). Email stays in Kratos. There is no invite table. Membership is Keto. The broker checks it through glue. sqlite `humans` is planted `self` only.

`device offer` wraps master to another machine's public key (`nacl/box`, same as fill). `Init` writes `device.key` and `wraps/`. `device accept` writes those, not plaintext `master.key`. Copy `vault.db` yourself. That is not sync and it does not pair a model.

TOTP is a field on the item, not a tool. The seed is sealed with the token. At Use, `pquerna/otp` mints a 6-digit code and the broker sets `X-TOTP`. The model never receives the seed or the code. There is no `get_totp`.

There is no `item get`. Secrets are injected at Use, not printed.

See [docs/SPEC.md](docs/SPEC.md) for the capability map and [docs/prior-art.md](docs/prior-art.md) for licensed libraries and the patterns we follow from Infisical, Bitwarden, OneCLI, 1Password, Aside, Entra, and MeowPass.

## License

MIT. Copyright 2026 Vortex NYC, Inc.
