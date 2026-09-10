# password-manager — agent contract

This is an agent-first credential broker. Read `docs/SPEC.md` and `docs/prior-art.md` before writing code.

## Ory \*

**Ory is the company.** We pin three of their products. They are not synonyms. We do not fork them. We do not rewrite them. Glue talks to them. The broker does not.

| Name | Job | Directory |
|---|---|---|
| **Kratos** | Humans. Email, password, recovery, session. The directory. | `identity/glue/kratos` (client) · `identity/kratos` (image) |
| **Hydra** | Tokens. “Is this proof real?” | `identity/glue/hydra` (client) · `identity/hydra` (image) |
| **Keto** | Org owner / member. Not grants. | `identity/glue/keto` (client) · `identity/keto` (image) |

**Glue** (`identity/glue`) wires those three. Official Ory Go clients are in `glue/kratos`, `glue/hydra`, `glue/keto` — that is the SDK. Glue itself does not import them so a switch is one directory per product. **Broker** is our product: items, agents, grants, inject.

Same UUID (`protocol.LocalOrgID`) is a join key in the vault, Kratos `organization_id`, and the Keto object. It is not three directories.

We do not run Oathkeeper, Keto as a grant engine, or a second user table.

## Load-bearing rules

1. **Agents never receive secrets.** Not in JSON, not in MCP, not in logs, not in audit. If a test can marshal a result and find the secret, the slice is broken.
2. **The grant is the object.** Org RBAC is who may *create* a grant. The grant is whether this principal may *Use* this item at this level. Humans, invites, sessions live in Ory. Identity-plane owner/member is Keto. sqlite `humans` is planted `self` only. The broker may call glue for member/owner checks. Do not put grants in Keto.
3. **Laptop is a cloud agent.** Same `Use` / `Approve` protocol. Local sockets are transport, not identity.
4. **Do not hand-roll what exists.** Crypto is `golang.org/x/crypto`. TOTP is `pquerna/otp`. MITM is `goproxy`. OIDC verify is `coreos/go-oidc`. OAuth refresh is `golang.org/x/oauth2`. Humans are pinned Ory Kratos + Hydra. Identity-plane owner/member is Keto. Fill and device pairing are `nacl/box`. SSH is `x/crypto/ssh/agent`. Do not fork Ory. Do not compile it into the broker. Do not put grants in Keto.
5. **Prior art, licensed use, not copies.** Reviewing open source and depending on a library under its license is legal. Being inspired by a product's pattern is legal. Copying their source into this tree is not. Infisical, Bitwarden, 1Password, Aside, Entra, OneCLI, Ory, KeePassXC-Browser are prior art.
6. **Go owns the product.** Policy, crypto, grants, inject, CLI, MCP, API, daemon. The web app is pnpm + Vite+. Native shells are thin: a sheet, a biometric, a forward. Chrome, Safari, iOS, and Android cannot do Face ID, passkeys, or autofill in Go.
7. **Tests first** for grant, inject, and leak. `go test ./...` is the Go suite. The web workspace is `pnpm` and `vp lint` / `vp fmt`.
8. No AI attribution in commits, PRs, or generated files.

## Current slice

OpenAPI factory. `docs/openapi/password-manager.openapi.json` is the contract. HTTP `/v1/items` and `/v1/use` (body + headers). CLI `use --body-file`. MCP `fetch` the same operation. Generated Go/TS/Python SDKs. Blume `/reference` via `apps/docs`. Never handwrite clients. No GetSecret.

Mint helper: `agent token NAME --secret-file --out-file`. JWT to disk. Never stdout. Then one live agent Bearer to `POST /v1/use`.

Item lifecycle and secret refs. `${NAME}` / `pwm://name` resolve only inside `run --inject` and child env. Archive, delete, tags, history, file BLOB (owner write to disk), grant `--expires`, owner `audit`, `gen`. MCP agent tools are still only `list_items` + `fetch`. No vaults. No 1Password. No iOS. No Railway this slice.

Cloud coding agents hit `https://pwm.vortex.nyc/mcp`. Same Streamable HTTP. Bearer after `agent bind` / `agent hydra`. Mint at `https://id.vortex.nyc` (Hydra public: token+JWKS). Not admin. Origin is the Mac Mini (Hydra + broker together). Cloudflare Tunnel, not Workers.

Keto is membership truth. Invite is owner-gated after bootstrap. Master is wrapped (`device.key` + `wraps/`), not a plaintext `master.key`. If Hydra is configured, Approve is ApproveOIDC. Login is Kratos `oauth2_provider`, not a glue HTTP hop. Hydra consent skip still needs glue AcceptConsent.
