# Prior art

Ideas we take. Code we do not copy. Licenses we respect.

| Source | License | What we take | What we leave |
|---|---|---|---|
| [Infisical Agent Vault](https://github.com/Infisical/agent-vault) | MIT | Agent as a named principal. Discover by name, never by value. Inject at HTTP edge. Scrub responses. `vault run` env pattern (later). | Their MITM/CA, Gorm, proposals UI, Infisical product coupling. |
| [Infisical Agent Proxy](https://infisical.com/docs/documentation/platform/agent-proxy/quickstart/credentials) | proprietary product | Placeholder substitution. Local proxy vs hosted proxy as the same protocol. | Their dashboard. |
| [OneCLI](https://github.com/onecli/onecli) | see repo | Per-agent rules at the network layer. Audit the request, not the secret. Bitwarden as a *source*, not the data model. | Rust/TS stack, Cognito. |
| [Bitwarden Agent Access](https://github.com/bitwarden/agent-access) | see repo | JIT request for one item. `run` injects env into a child. TOTP *lives on the item* (later). | Returning `{password, totp}` to the caller. Pairing that requires a laptop for cloud agents. |
| [1Password Agentic Autofill](https://www.1password.dev/agentic-autofill) | proprietary | HITL approval names the item. Fill happens outside the model. | Always-level-1. Browser-only. Closed. |
| [Aside](https://aside.com/features/password-manager) | proprietary | Passkey + TOTP completed for the agent without exposing material. | Their browser. Crude always/never policy. |
| [Microsoft Entra Agent ID](https://learn.microsoft.com/en-us/entra/agent-id/what-are-agent-identities) | proprietary | Agent is a directory object with an owner. Workload identity, not a copied master password. | Entra tokens only. Not a vault. |
| [MeowPass](https://github.com/meowrithm/meowpass-cli) | see repo | Go CLI + MCP. Tool not value. Argon2id + AES-GCM (we use x/crypto XChaCha20-Poly1305 instead). | `.env` product. |
| [Authsome](https://github.com/agentrhq/authsome) | see repo | OAuth login once; refresh stays in the broker. | Local-only. |

If a library already does the job, depend on it:

- AEAD: `golang.org/x/crypto/chacha20poly1305`
- TOTP (later): `github.com/pquerna/otp`
- HTTPS MITM (later): `github.com/elazarl/goproxy`
- SQLite (later): `modernc.org/sqlite`
- Human IdP: Vortex Auth / Better Auth as JWT issuer — do not rebuild org invites here
