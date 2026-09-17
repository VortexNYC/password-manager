# The layer

Written 2026-09-13. Not a slice. Do not scaffold plugins, a marketplace, or Sign in with Veil from this file. Fill is `docs/fill.md`. Identity stays Ory. Grants stay the grant.

**One control plane, two protocols, many destination accounts.** Humans: we are the passkey authenticator. Agents: grant → inject → audit. Destinations don’t have to know we exist.

Veil is an agentic vault. It is also the **policy plane for a principal** — a human and their agents — over every service they already have. That is the layer above Better Auth and above Cloudflare Access. It is not another social button. Do not say “one account that signs into anything.” That sentence builds Clerk.

## Two problems, not one

“No more hundreds of accounts” is two claims glued together.

1. **I don’t want hundreds of passwords.** Passkeys + a vault. Each site still has an account. The password dies. Fill (`docs/fill.md`) is that door.
2. **I don’t want hundreds of identity landlords.** That’s federation. GitHub / Linear / Stripe must accept an assertion from Veil that you are you. That is an IdP. They will not switch off Google for us. The protocol already exists (OIDC). Capture did.

The unified layer we own is **authorization, not identity.** One Veil identity (human at Kratos, agent at Hydra). Capabilities underneath: this agent may Use `linear` for 7 days, this host, this action, Touch ID for fill, never a secret on MCP, audit row. Deep control lives on the grant, not on “I am Shlomo.”

## Altitude

Better Auth is a library **inside someone else’s app**. Apple, Google, GitHub — those buttons are *their* OAuth. The app stores *their* user row. You still have an account per app. Cloudflare Access is the same shape with a smaller landlord: they store the session and the policy.

Adding “Sign in with Veil” to that list is going **down** into their layer. Clerk. We lose to Google on their field. Consumer apps use Veil Auth (better-auth + Convex). Veil does not become Better Auth.

The layer **above**: the principal’s policy plane. You sign into Veil. That is the only identity *you* operate. Cloudflare, Linear, GitHub are **destinations**. Access lives here: who may use this, which agent, which action, until when, audit. Their “create an API token, dump it in a dashboard” is a grant on the item.

Until they plugin, we don’t need them. Hold the token. Inject it. Fill the dashboard login. Speak *their* OAuth: refresh stays in the broker, inject the access token (`oauth` in SPEC). That’s the altitude above Better Auth without their permission.

The plugin is so *they* mint and revoke through our UX. Optional sugar. The flywheel is agent runtimes (no Sign in with Google for Cursor) plus humans who want the same vault to fill Chrome. Destinations care after that.

“Cloudflare security protocols live in Veil” means **who may call `api.cloudflare.com`, from which agent, with what TTL, and the receipt.** It does not mean we run their WAF. Names/addresses/cards are fill, not a PIM.

## Drawings

```
TODAY — each service is the landlord
====================================

  you ──┬── Sign in with Google ──► App A (their user row, their session)
        ├── Sign in with Apple  ──► App B
        ├── Cloudflare Access   ──► App C   policy lives at Cloudflare
        └── email+password+2FA  ──► App D   token lives in their dashboard

  Better Auth sits INSIDE each app. It only adds more logos.
  You still have N accounts. N policy planes. N token pages.
```

```
THE TRAP — another button on their list
========================================

  App ── Better Auth ──┬── Google
                       ├── Apple
                       ├── GitHub
                       └── Veil     ← Clerk. we lose to Google.

  They still store the user. They still own the policy.
```

```
THE LAYER — Veil is the policy plane. they plug UP.
===================================================

                         ┌─────────────────────────────────────┐
                         │              VEIL                    │
                         │  1 control plane. this is the door. │
                         │                                      │
                         │  items     grants      audit          │
                         │  (secrets)  agent×item  who/when     │
                         │             action TTL  no secrets   │
                         └──────────────┬──────────────────────┘
                                        │
              humans                    │                 agents
         fill / passkeys                │              Use / inject
         (cursor in the field)         │           (secret never in model)
                                        │
              ┌─────────────┬──────────┴──────────┬─────────────┐
              ▼             ▼                     ▼             ▼
         Cloudflare      Linear               GitHub         Stripe
         plugin or       plugin or           plugin or      plugin or
         just the item   just the item        just the item   just the item

  Plugin = they provision/revoke through us.
  No plugin = we still hold the key and inject.
```

```
WHAT LIVES WHERE
================

  Ory (Kratos / Hydra)     who is this human / this agent
  Veil origin               what secrets exist, which URI
  Veil grants               what this principal may do
  Destination (CF, Linear)  their product (WAF, issues, git)
                           NOT the user’s access control plane
```

```
ONE CONTROL PLANE  (the UX)
===========================

  Veil
   ├─ cloudflare      grant: cursor  fetch  7d     last use 19:04 allow
   ├─ linear          grant: cursor  fetch  7d
   ├─ github          grant: —        (human fill only when the item is a PAT)
   └─ dash login      fill / passkey  Touch ID

  You manage access here.
  You do not open 100 dashboards to mint tokens.
  You do not Sign in with Veil on their website.
  Their session is still theirs. We write it or we inject past it.
```

## Locks

- Broker verifies a token. It does not issue one. Hydra issues agent identity. Kratos is the human door. `Workload` verifies someone else’s issuer and maps `(issuer, subject)` to an existing agent.
- The grant is the micro-auth primitive. Per item, per principal, `fetch` / `env`, allow / deny / need_approval. Tighten later: method (GET vs DELETE), rate, `need_approval` on mutating calls. Not org RBAC. Not Better Auth. Not Keto tuples.
- Fill is not MCP. Agents move the cursor. They never receive the secret. Cards `Injects() == false`. No grant means buy. OAuth refresh, passkeys, and API keys are one grant surface, not three products.
- Audit is `GET /v1/events` / `veil audit`: agent, item, action, decision, time. Next honest row is method + host + path + status on `Use` (bodies scrubbed). “Opened Linear issue ABC” is their audit, not ours.
- Marketplace, if it exists, is destinations minting/revoking through the SPA. Not SSO. Not 1Password Connect (no dumping the vault toward their process).
- Tip of the spear: finish fill, make grants and audit readable, then OAuth-refresh as the first destination that isn’t a static key. Plugin catalog last.

## Not this, not now

Plugins. A public marketplace. Sign in with Veil on third-party sites. Swallowing Cloudflare Zero Trust / WAF. Becoming the internet’s login button. A second identity product next to Ory.
