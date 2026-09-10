# Prior art

Reviewing open source and using it under its license is legal. Being inspired by a product's patterns, solutions, and methods is legal. Copying their source into this tree is not.

Ideas we take. Code we do not copy. Licenses we respect.

| Source | License | What we take | What we leave |
|---|---|---|---|
| [Infisical Agent Vault](https://github.com/Infisical/agent-vault) | MIT | Agent as a named principal. Discover by name, never by value. Inject at HTTP edge. Scrub responses. `vault run` env into a child. | Their MITM/CA, Gorm, proposals UI, Infisical product coupling. |
| [Infisical Agent Proxy](https://infisical.com/docs/documentation/platform/agent-proxy/quickstart/credentials) | proprietary product | Placeholder substitution. Local proxy vs hosted proxy as the same protocol. | Their dashboard. |
| [OneCLI](https://github.com/onecli/onecli) | see repo | Per-agent rules at the network layer. Audit the request, not the secret. Bitwarden as a *source*, not the data model. | Rust/TS stack, Cognito. |
| [Bitwarden Agent Access](https://github.com/bitwarden/agent-access) | see repo | JIT request for one item. `run` injects env into a child. TOTP lives on the item; we mint at inject and never return the code. | Returning `{password, totp}` to the caller. Pairing that requires a laptop for cloud agents. |
| [1Password Agentic Autofill](https://www.1password.dev/agentic-autofill) | proprietary | HITL approval names the item. Fill happens outside the model. | Always-level-1. Browser-only. Closed. |
| [Aside](https://aside.com/features/password-manager) | proprietary | Passkey + TOTP completed for the agent without exposing material. | Their browser. Crude always/never policy. |
| [Microsoft Entra Agent ID](https://learn.microsoft.com/en-us/entra/agent-id/what-are-agent-identities) | proprietary | Agent is a directory object with an owner. Workload federation: trust an external issuer, map subject to a principal. | Entra tokens only. Not a vault. Becoming an IdP. |
| [MeowPass](https://github.com/meowrithm/meowpass-cli) | see repo | Go CLI + MCP. Tool not value. Argon2id + AES-GCM (we use x/crypto XChaCha20-Poly1305 instead). | `.env` product. |
| [Authsome](https://github.com/agentrhq/authsome) | see repo | OAuth login once; refresh stays in the broker. Access token injected, never returned. | Local-only. Their token client — we use `golang.org/x/oauth2`. |
| [Ory Kratos](https://github.com/ory/kratos) | Apache-2.0 | Directory: passwords, sessions, recovery, invites. Pin the official image. | Their source in this tree. A user table. |
| [Ory Hydra](https://github.com/ory/hydra) | Apache-2.0 | Issuer. Login and consent are a hole we fill. | fosite. Compiling Hydra into the broker. |
| [Ory Keto](https://github.com/ory/keto) | Apache-2.0 | Identity-plane owner/member. Pin the official image. | Grant tuples. Compiling Keto into the broker. |
| [Ory Elements](https://github.com/ory/elements) | Apache-2.0 | Screens in `identity/login` only. Follows the identity schema. | Using it inside the broker. Auth.js. |
| [KeePassXC-Browser](https://github.com/keepassxreboot/keepassxc-browser) | GPL-3.0 | The fill wire. Thin extension, native messaging, local process answers. Passkeys included. | Their extension in this tree. KeePassXC as the vault. `gkpxc` — that is a client of their database. |

If a library already does the job, depend on it:

- AEAD: `golang.org/x/crypto/chacha20poly1305`
- TOTP: `github.com/pquerna/otp`
- HTTPS MITM: `github.com/elazarl/goproxy`
- SQLite: `modernc.org/sqlite`
- OIDC verify: `github.com/coreos/go-oidc/v3` — the broker does not issue tokens
- OAuth refresh: `golang.org/x/oauth2`
- SSH agent: `golang.org/x/crypto/ssh/agent`
- Logs: `log/slog` JSON to stderr. Railway HTTP logs (`railway logs --http`) are the request log. Traces: `otelhttp` + OTLP HTTP. Sink is PostHog (`/i/v1/traces`, org already has it). Skip `/health` and `/ready`. No query string, no Authorization, no body on spans. Not zap. Not a collector we run. Not Langfuse.
- Humans: pinned Ory Kratos + Hydra + Keto. Glue is their Go clients. Screens are Ory Elements in `identity/login` only. Not Zitadel. Not Better Auth. Not a fork of Ory. Not Oathkeeper. Not Talos. Not their agent-security product. Grants are not Keto tuples.
