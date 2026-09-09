# password-manager — agent contract

This is an agent-first credential broker. Read `docs/SPEC.md` and `docs/prior-art.md` before writing code.

## Load-bearing rules

1. **Agents never receive secrets.** Not in JSON, not in MCP, not in logs, not in audit. If a test can marshal a result and find the secret, the slice is broken.
2. **The grant is the object.** Org RBAC is who may *create* a grant. The grant is whether this principal may *Use* this item at this level.
3. **Laptop is a cloud agent.** Same `Use` / `Approve` protocol. Local sockets are transport, not identity.
4. **Do not hand-roll what exists.** Crypto is `golang.org/x/crypto`. TOTP will be `pquerna/otp`. MITM will be `goproxy`. Identity is an IdP we verify, not a user table we invent.
5. **Steal ideas, not files.** Infisical/Bitwarden/OneCLI are prior art. Do not copy their source into this tree.
6. **Go only** in this repo except unavoidable native shells (Chrome/iOS/Android), which stay thin.
7. **Tests first** for grant, inject, and leak. `go test ./...` is the suite. `pnpm` does not apply here.
8. No AI attribution in commits, PRs, or generated files.

## Current slice

Infisical broker + MeowPass CLI/MCP + goproxy HTTPS_PROXY. SQLite at `--home` / `PWM_HOME`. MCP and proxy are bound to one agent. Next: TOTP.
