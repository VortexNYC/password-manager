# Spec: password-manager

Agent-first credential broker. One protocol. Two grant levels. Secrets never enter the model.

## Objective

Developers have more agents than they have a way to say “this bot may be Stripe, that bot may not be Gmail.” This repo is that way.

Not Better Auth. Not a 1Password clone. Humans/orgs/SSO stay an identity plane we consume. This plane is items, agent principals, grants, and inject.

## Capability map

| Module id | Responsibility | Depends on | Steal from |
|---|---|---|---|
| protocol | Resolve / Use / Approve. Agent never sees Secret. | — | Bitwarden Agent Access shape (request item, not vault) |
| grant | Per-item level-1 (human last step) vs level-2 (agent exclusive). Org-owned vs user-owned agents. | protocol | Entra Agent ID (agent as principal); OneCLI (per-agent rules) |
| broker | Fetch injects credential at the edge; response scrubbed | protocol, grant | Infisical Agent Vault / Agent Proxy |
| store | Encrypted item material; audit without secrets | protocol, crypto | MeowPass (Go E2E box); Infisical (SQLite later) |
| crypto | AEAD wrap only | — | `golang.org/x/crypto/chacha20poly1305` — do not invent |
| proxy | HTTPS_PROXY MITM so unmodified SDKs work | broker | Infisical MITM; use `elazarl/goproxy` not a hand-rolled CONNECT |
| mcp-cli | Same protocol on stdio, HTTP MCP, CLI | protocol, broker | MeowPass CLI; Infisical `vault run` |
| totp | Mint at use-time, inject, never return the code | broker | Bitwarden item field; 1Password fill |
| passkey | Broker completes WebAuthn; model never holds the key | broker | Aside |
| identity | Humans, orgs, invitations, SSO as an IdP we verify | — | Vortex Auth / Better Auth as JWT issuer, not a rewrite |
| workload | Laptop == cloud. Device key or provider OIDC. | grant, identity | Entra workload federation; Infisical named agent tokens |

Build order: protocol → grant → broker → store/crypto → mcp-cli → proxy (this commit) → totp → workload → passkey → identity.

## Commands

```
make test
make vet
make ci
go test ./...
go run ./cmd/password-manager version
```

## Project structure

```
cmd/password-manager    cobra CLI + MCP stdio
internal/app            facade CLI and MCP share
internal/cli            human commands (no --secret on argv)
internal/mcpserver      official Go MCP SDK
internal/proxy          elazarl/goproxy MITM; per-vault CA; fail closed
internal/protocol       the one API
internal/grant          evaluation
internal/broker         the only code that touches secrets
internal/store          memory + sqlite (secrets sealed)
internal/crypto         x/crypto wrapper
internal/scrub          agent-visible redaction
docs/                   spec + prior art
```

Native Chrome/iOS/Android shells are out of this repo until the protocol is boring.

## Testing

- `go test ./...` is the suite. Stdlib only.
- Every Use/Approve path asserts the secret is absent from JSON of the result and of the audit log.
- Prefer httptest and the memory store over mocks.

## Boundaries

- Always: tests before claiming a slice is done; leak assertions on agent-visible types; stdlib or x/crypto for crypto.
- Ask first: new item kinds, new dependencies, changing the grant model.
- Never: return a secret to an agent; add a Reveal API on the agent path; copy Infisical/Bitwarden source; hand-roll AEAD, TOTP, or an HTTP MITM.

## Success criteria (current slice — MeowPass CLI/MCP + sqlite)

- [x] Agent is a principal, not a user with a password.
- [x] Level 2 fetch injects Bearer token; agent result and audit contain no secret.
- [x] Level 1 fetch returns need_approval until a human Approves.
- [x] Fetch to a host not on the item is denied.
- [x] Wrong agent is denied.
- [x] Crypto is x/crypto XChaCha20-Poly1305.
- [x] SQLite persists items; plaintext secret is not on disk.
- [x] CLI: init, item add (secret-file/stdin), agent, grant, use, approve.
- [x] MCP `fetch` / `list_items` bound to PWM_AGENT; output JSON has no secret.
- [x] No agent-facing Reveal / `item get` / `--secret` argv.
- [x] HTTPS_PROXY MITM via goproxy; per-vault CA; inject + scrub; unknown hosts denied.
- [x] `run --agent NAME -- CMD` sets HTTP(S)_PROXY and CA env. Vault secret is not in env.

## Open questions

- Product name vs repo name `password-manager`.
- Hosted identity plane: Vortex Auth vs a Go OIDC verifier in-tree.
