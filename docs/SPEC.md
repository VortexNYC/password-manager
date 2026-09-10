# Spec: Veil

Agent-first credential broker. One protocol. Two grant levels. Secrets never enter the model.

The product is Veil. Repo and CLI stay `password-manager` in VortexNYC until a rename.

## Objective

1Password is the company we are taking customers from. Not Infisical. Not Vault. Not Bitwarden-the-enterprise.

Who: developers, their agents, solo people, families, small teams, startups under 100 people. Vortex is the first of those, not a different product.

The wedge is agents: a bot may be Stripe and may not be Gmail. Humans in that same org still need logins, TOTP, fill, SSH, sharing. One protocol. Two grant levels. Secrets never enter the model.

Not a 1Password clone. Same customers, different machine. The broker plane is items, principals (human and agent), grants, and inject. It verifies a token. It does not issue one.

Humans live in a sibling plane in this same repo. That plane pins official Ory Kratos, Hydra, and Keto. It does not fork them and does not compile them into the broker.

## Doctrine

Dogfood is Vortex (agents on Flue / Codex / Cursor, humans on this Mac). The market is everyone 1Password sells Individual / Families / Teams to, plus startups under 100. We do not build for 1Password Enterprise: SCIM, Privileged Access, Device Trust, AWS Secrets Manager sync, a 10k-seat admin console.

The grant is the object. Use is the only way a secret is touched. Grants are per item. A bank is level 1 forever. A Stripe test key is level 2. A family member is a human principal with grants, not a second vault type.

Go owns policy, crypto, grants, inject, CLI, MCP, API, and the daemon. The SPA is every real human option: items, grants, agents, invites, audit, settings. Phone is add a password or fill one — nothing else. Agents use CLI / MCP / SDK. OS integration is a stupid-light background binary, not a desktop app. Customers fill Chrome / Edge / Firefox with a **Veil-branded extension** we ship (slice 37). The Go process is the native host. Slice 26 proves that host against origin using store keepassxc-browser — same wire, not the product chrome. Touch ID at fill time lives in the host. SSH agent is the same Go. Native SDK, Tauri, and Electron are not a product. Apple/Google still tax Safari / iOS / Android fill with a containing .app / APK that hosts the extension and the two phone screens. It is not a second admin console. Call it Go-only in the deck. Do not believe it in the repo.

Do not become 1Password's architecture (vaults, Connect, `op`, import). Take their customers. Do not run Vaultwarden. Do not put this server on Workers.

Take the patterns that work, and stop:

- Ciphertext is what a shell may cache. The injector is what decrypts.
- TOTP lives on the item and is minted at use.
- Shells speak Resolve / Use / Approve. They do not grow a second API.

Add back only: logins, TOTP, API keys, OAuth refresh, SSH, env into a child, passkeys, grants, audit.

Level 1 last step is a human: CLI, Touch ID, Face ID, or a push. Level 2 finishes the ceremony without that human. Both still inject outside the model.

A Mac unlock does not authorize a cloud agent. A device pairing does not pair a model.

Local inject is the default. A hosted proxy exists only for a runtime with no daemon.

SMS, email OTP, Duo, and a hardware key that must be touched in a data center are not level 2. A level-2 Gmail that needs a text is a stuck agent.

Passkeys: we are the authenticator when the site is someone else. Level 1 user verification is the human. Level 2 user verification is the grant. Sites that demand hardware attestation will refuse. Say that.

## Capability map

| Module id | Responsibility | Depends on | Prior art |
|---|---|---|---|
| protocol | Resolve / Use / Approve. Agent never sees Secret. | — | Bitwarden Agent Access shape (request item, not vault) |
| grant | Per-item level-1 (human last step) vs level-2 (agent exclusive). Org-owned vs user-owned agents. | protocol | Entra Agent ID (agent as principal); OneCLI (per-agent rules) |
| broker | Fetch injects credential at the edge; response scrubbed | protocol, grant | Infisical Agent Vault / Agent Proxy |
| store | Encrypted item material; audit without secrets | protocol, crypto | MeowPass (Go E2E box); Infisical (SQLite later) |
| crypto | AEAD wrap only | — | `golang.org/x/crypto/chacha20poly1305` — do not invent |
| proxy | HTTPS_PROXY MITM so unmodified SDKs work | broker | Infisical MITM; use `elazarl/goproxy` not a hand-rolled CONNECT |
| mcp-cli | Streamable HTTP MCP. Bearer is the agent. CLI for humans. | protocol, broker | MCP spec 2025-03-26; MeowPass CLI; Infisical `vault run` |
| totp | Mint at use-time, inject, never return the code | broker | Bitwarden item field; 1Password fill |
| passkey | Two jobs. Site side when we are the relying party. Fill when the site is someone else. | broker | Site: `go-webauthn` or Kratos. Fill: native-messaging + nacl box, our host. Product chrome is the Veil extension. |
| workload | Laptop == cloud. Verify provider OIDC; map subject to an existing agent. | grant | Entra federation; `coreos/go-oidc` |
| oauth | Refresh stays in the broker. Inject the access token. | broker | Authsome; `golang.org/x/oauth2` |
| humans | Sibling plane. Directory, issuer, identity-plane RBAC. | identity schema, login UI | Official Ory Kratos + Hydra + Keto images. Go clients for the glue. |

Build order for what is missing: 1Password displacement for the people above. Vortex remains the only org in this vault until that is proven. Do not start iOS until fill on this Mac Uses origin items. Families live on phones — that is the limiter after Mac fill, not a reason to start an app this week. Do not invent a second org in sqlite to fake a market.

## How we fill the repo

One slice. One library, image, or protocol. Glue only.

1. Name the missing part from the parts list.
2. Open the product we already assigned. Use its library, image, or protocol.
3. Write only the seam that makes the grant true: inject, verify, or Approve.
4. Prove it with a test that the secret is absent from agent output.
5. Stop. Do not add a second API, a second store, or a framework.

If the reference is an image, pin it. If it is a library, import it under its license. If it is a protocol, speak it. Do not copy their source into this tree.

The next slices, in this order, and nothing else until each is proven:

```
1  glue                 written. kratos-client-go + hydra-client-go
2  first-party client   written. Hydra admin, consent skipped
3  broker trusts Hydra  written. internal/human, go-oidc at our Hydra
4  Approve              written. ApproveOIDC is that Hydra subject.
                         planted `self` is tests and CLI without Hydra.
5  agent Hydra client   written. client_credentials, jwt, not a Kratos human
6  laptop socket        written. unix HTTP. Bearer is the Hydra JWT
7  fill host            written. native-messaging + nacl box. we answer
8  ssh                  written. x/crypto/ssh/agent. key never leaves
9  env into a child     written. Infisical vault run. never the prompt
10 owner-key wrap       written. one DEK per owner. master unwraps
11 org and invites       written. Kratos recovery code. no vault table
12 device pairing        written. nacl box wrap of master. not iOS
13 keto                  written. owner/member. not grants. not iOS
14 one org id            written. protocol.LocalOrgID in vault, Kratos, Keto
15 remote MCP            written. Streamable HTTP. Bearer is the agent.
                         cursor, devin, pi, opencode. same URL.
16 cloud coding agents   written. https://veil.nyc/mcp
                         Cloudflare Tunnel, not Workers. not iOS
17 public Hydra mint     written. https://id.veil.nyc token+JWKS.
                         not admin. cloud agents client_credentials.
18 Mini origin            written. Hydra+broker on the Mini.
                         Tunnel there. laptop is not the origin.
19 item lifecycle + refs written. ${NAME}/pwm:// in run --inject.
                         archive/delete/history. Grant.ExpiresAt.
                         file BLOB owner-write. audit CLI. passgen CLI.
                         not MCP. not vaults. not 1Password.
20 OpenAPI factory        written. docs/openapi is the contract.
                         GET/POST /v1, CLI use --body-file, MCP fetch.
                         Go/TS/Python SDKs + Blume /reference generated.
                         Never handwrite clients. No GetSecret.
21 mint helper            written. agent token --secret-file --out-file.
                         JWT to disk. never stdout. live POST /v1/use.
22 laptop MCP adapter     written. `mcp stdio` against origin HTTP.
                         Cursor live: list_items + fetch GitHub /user
                         allow/200, token absent from the tool payload.
                         Codex/Devin laptop same. Not `${file:}`.
23 one store              written. origin is the vault. PWM_ORIGIN CLI
                         item/grant/list/fill HTTP. Never opens sqlite.
                         PrincipalFromOIDC: bound agent, else human+Keto.
                         POST /v1/items and /v1/grants are owner. Secret
                         in create request, never in response. Fill path
                         /v1/fill/logins is human native-host only, not
                         OpenAPI, not MCP. Chrome URI fill is slice 26.
24 human mint             written. `human login --out-file`. Hydra PKCE.
                         ID token to disk. never stdout. Fill and owner
                         HTTP use PWM_HUMAN_TOKEN_FILE, not the agent JWT.
                         Live mint needs identity on origin (first-party
                         Hydra client, Kratos, Keto). Not MCP.
25 identity on origin      written. Sibling Railway services: official
                         Kratos, Keto, glue, Hydra. Login UI is Cloudflare
                         Workers (`veil-login`) at login.veil.nyc.
                         accounts.veil.nyc is Kratos public. consent.veil.nyc
                         is glue. Hydra URLS_LOGIN public. pwm PWM_KETO_*.
                         First-party client password-manager. Live human mint.
                         Grants stay in the vault. Not Keto. Not one soup.
26 chrome URI fill        written. store keepassxc-browser + Go host
                         against origin. Human JWT. a real Chrome field
                         Uses a veil.nyc item. FillEntry.Login is the
                         fill username in the sealed envelope, not
                         item.Name. Empty is honest. not MCP. not list.
                         Touch ID in the host is still open. Product
                         chrome is slice 37, not this listing.
27 totp enroll            written. `totp enroll --out-file --qr-file`.
                         otpauth QR is a PNG. seed then item add --totp-file.
                         not MCP. not a screenshot of the seed.
28 kratos MFA             not written. totp and/or webauthn on Kratos
                         so a human unlocking Veil is not password+email
                         only. Official Kratos methods. Not a DIY MFA.
29 human grants           not written. family / small team: grant an item
                         to another Kratos human. Same grant object.
                         not a family vault. not collections.
30 SPA vault              not written. Cloudflare. shadcn from Core.
                         every human option: items, grants, agents,
                         invites, audit, settings. not Ory Elements.
                         not Native SDK / Tauri / Electron.
31 passkeys fill          not written. passkeys-* on the same host
                         after slice 26. customers use the Veil
                         extension (37). store listing is the wire.
32 Mac helper             not written. menu-bar accessory .app.
                         no vault UI. Settings > Passwords.
                         ASCredentialProvider: Safari + native Mac apps.
                         not Chrome. Chrome stays the browser
                         extension (26 wire, 37 product).
33 iOS app                not written. proper app. add + fill only.
                         ASCredentialProviderViewController. Face ID
                         in that process. not grants/agents/audit.
34 Android app            not written. proper app. add + fill only.
                         AutofillService / Credential Manager.
                         not grants/agents/audit.
35 Windows helper         not written. tray. Chrome still the Veil
                         extension.
                         Revisit then: WebAuthn plugin (passkeys, Win11),
                         Auto-Type, whatever shipped since this spec.
                         Do not assume an Apple-style password fill API.
36 Linux helper           not written. tray. Chrome still the Veil
                         extension.
                         Revisit then: Secret Service (store, not fill),
                         Auto-Type / portals, whatever shipped since.
                         Do not assume a Freedesktop Autofill portal.
37 Veil browser extension not written. Chrome / Edge / Firefox.
                         Our name, our listing. Speaks the same
                         native-messaging + nacl box host as 26.
                         Replaces store keepassxc-browser for
                         customers. Do not copy keepassxc-browser
                         into this tree (GPL-3). Not this week.
```

Identity screens exist (Ory Elements at login.veil.nyc). Do not restyle them. Do not add a Go web framework. The vault SPA is slice 30. Phone is slices 33–34 (add + fill). Mac helper is slice 32. Windows/Linux helpers are 35–36 and re-check the OS APIs on that slice, not now. The Veil browser extension is slice 37. Do not wrap the SPA in Native SDK / Tauri / Electron. iOS after slice 26. Not this week.

## What the broker is

One Go process. Items, agents, grants, inject. A token proves who is calling. `coreos/go-oidc` checks it. The grant decides Use. The broker does not issue human identities, invites, or sessions.

## Ory \*

Ory is the company. Three images. Not three names for one thing.

| | What it is | One question it answers | Code |
|---|---|---|---|
| **Kratos** | Human directory | Who is this person (email, session, recovery)? | `identity/glue/kratos` |
| **Hydra** | Token server | Is this token valid? | `identity/glue/hydra` |
| **Keto** | Owner / member graph | Is this Kratos id in the org? An owner? | `identity/glue/keto` |
| **Glue** | Our adapter process | Wires the three. SDKs live in the three dirs. | `identity/glue` |
| **Broker** | This product | Items, agents, grants, inject. Never Kratos. | `internal/` |

Do not put grants in Keto. Do not put humans in sqlite except planted `self` (laptop, no Hydra).

## Planes

Three processes. Do not merge them.

```
Ory                         Glue                      Broker
  Kratos: humans, email        invite + recovery        items, agents, grants
  Hydra: tokens                keto owner/member       inject, Use, Approve
  Keto: owner / member         hydra clients            member check via glue
                               consent accept
```

One org: `protocol.LocalOrgID` in the vault, Kratos `organization_id`, and the Keto object. A second company is a new UUID when a second tenant exists.

Keto is membership. sqlite `humans` is planted `self` only. Glue writes owner/member. The broker calls glue `IsMember` (Keto) before ApproveOIDC. The grant is not a Keto tuple. The broker never calls Kratos.

The CLI planted human `self` is the laptop stand-in when Hydra is not configured. A real Approve is a Hydra subject. If `PWM_HYDRA_ISSUER` is set, `Approve` without an ID token fails.

Device pairing wraps master to a device public key. `Init` writes `device.key` and `wraps/`. There is no plaintext `master.key`. Copy `vault.db` yourself. That is not sync.

## Parts

Every part of the machine. Who fills it. Whether it exists. Do not start the next slice until this list is the one we are building against.

```
human
  directory          Kratos image          pinned, not the running product
  password           Kratos                same
  recovery           Kratos code flow      same
  mail               Kratos courier        mailpit in compose, not a product sender
  who a human is     our schema            email only, on disk
  screens            Ory Elements on Vite+  written. React + TanStack Router.
  glue               kratos-client-go      written. identity/glue
                     hydra-client-go        login is Kratos oauth2_provider.
                                           Hydra consent still hits glue AcceptConsent.
  issuer             Hydra image           pinned. urls.login is Kratos browser login
  first-party client Hydra admin           written. skip_consent. redirect is the broker
  token the broker   go-oidc             written. internal/human. PWM_HYDRA_ISSUER
  trusts
  who may Approve    Hydra subject         written. ApproveOIDC. planted `self` is tests/CLI without Hydra

agent
  record             this store            built. CLI agent add
  cloud proof        go-oidc workload      built. issuer+subject bind
  hydra client       Hydra admin          written. client_credentials. jwt. not a Kratos human
  laptop proof       unix socket           written. Bearer JWT. not a name. CLI `serve`
  session            none                  agent never holds a human session

item
  sealed store       x/crypto + sqlite     built. one key per owner. master unwraps.
  api key            broker inject         built
  oauth refresh      golang.org/x/oauth2   built
  totp               pquerna/otp           built. mint at inject
  passkey            native host           written. get-logins + get-totp
                     Veil extension        slice 37. store listing is 26.
                     go-webauthn           only if we are the site. not this slice
  ssh                x/crypto/ssh/agent    written. CLI `ssh`. key never leaves
  file               sealed BLOB          written. owner `item write --out-file`.
                                           not MCP. not env.
  history            item_versions          written. sealed blob. no secret in JSON
  tags               owner labels         written. not ACL. grants are ACL
  archive            archived flag        written. hidden from Use, list, fill

use
  grant              this grant package    built. level 1 and level 2
  approve            this broker           built against the local human
  inject             goproxy + child env   built. vault run never prints
                     ${NAME} / pwm://      written. `run --inject src:dest`. fail closed
  share              Grant.ExpiresAt     written. `grant add --expires`. forever if unset
  mcp / cli          this process          built. Streamable HTTP is origin.
                                           Bearer is the agent. cloud is that URL.
                                           Cursor cannot interpolate Bearer;
                                           `mcp stdio` is the laptop adapter
                                           over origin HTTP. not a second protocol.
                                           stale Hydra JWT is reminted via
                                           client_credentials from PWM_HYDRA_SECRET_FILE.
                                           not OAuth refresh_token. not ory/mcp.
  scrub / audit      this process          built. `audit` is owner CLI. not MCP
  passgen            crypto/rand           written. CLI `gen`. not MCP. not a vault item


org
  humans / email     Kratos               written. identity id is the FK
  invites            Kratos              written. recovery code. CLI `human invite`
                                           no invite table. no sqlite invite rows
  membership         Kratos identity       written. Keto is truth. glue IsMember.
                                           sqlite humans is planted self only
                                           Invite is owner-gated after bootstrap
  org directory       protocol.LocalOrgID written. same UUID in vault, Kratos,
                                           Keto. No CreateOrganization on this pin.
  identity RBAC      Keto                 written. Organization owners/members.
                                           glue writes. broker calls glue for
                                           member/owner only. Grants are not
                                           Keto tuples.
  who owns an agent  owner fields          written. owner is the human id
  who may Use        the grant            built. not org RBAC. not Better Auth

device
  pairing            nacl box            written. wrap master to a device
                                           public key. device.key + wraps/.
                                           not plaintext master. not a second
                                           vault. not iOS

computer
  vault UI           the SPA           chosen. Cloudflare. shadcn from Core.
                                           every human option lives here.
                                           not Native SDK. not Tauri. not Electron.
                                           not the phone.
  host               Go native host   written. native-messaging + nacl box.
                                           background. SSH agent. Touch ID at
                                           fill still open.
  chrome/edge/firefox extension       required. Veil ships it (slice 37).
                                           Chromium does not call
                                           Apple/Windows AutoFill for HTML
                                           forms. do not delete this.
                                           store keepassxc-browser is the
                                           slice-26 wire only.
  mac helper         menu-bar .app    later. accessory, no vault UI.
                                           Settings > Passwords. Safari +
                                           native Mac apps via
                                           ASCredentialProvider. not Chrome.
  win/linux helper   tray binary      later. same Go.
                                           Windows: WebAuthn plugin is
                                           passkeys, not password fill into
                                           Discord. Linux: Secret Service
                                           is a store; apps fetch, we do
                                           not fill. Native app fill on
                                           both is Auto-Type (keystrokes).
                                           Chrome still the extension.
phone
  add                new login         not this week. one form.
  fill               OS extension      not this week. ASCredentialProvider /
                                           AutofillService. Face ID in that process.
  not                grants, agents,  those are the SPA. the stub .app/APK
                     audit, SSH,        exists to host add+fill. it is not
                     settings            an admin console.
```

These are locked. The reference is the solution. Use it.

```
agent credential
  already speaks OIDC          go-oidc workload bind
  does not                     Hydra client. not a Kratos human. written.
                               client_credentials, jwt access token, bind issuer+sub
  bind                         issuer+subject to an agent that already exists
  laptop socket                presents that same client credential. written.

who may create a grant
  the owner of the agent       that human's id
  the CLI is the local stand-in

where the vault lives
  one broker process
  laptop or hosted
  same protocol. no second vault. no sync

how Approve reaches the human
  a screen that names the item
  it calls Approve
  the CLI stays for tests and the local stand-in
```

Passkey at a site is fill. The wire is native messaging + `nacl/box`. Our process is the native host. We do not use KeePassXC as the vault. Slice 26 proves the host with store [keepassxc-browser](https://github.com/keepassxreboot/keepassxc-browser). Customers get a Veil-branded extension (slice 37). Do not copy keepassxc-browser into this tree (GPL-3). Fill may write a secret into the page. It never returns a secret to an agent.

`go-webauthn` is only the site side, when this product is the relying party. Kratos already does that for human login.

Missing, and the owner is already named:

```
screens
  who          Ory Elements in identity/login
  what         register, login, recovery, settings. one app. it follows the schema.
  when         first

computer
  who          Go native host (exists). Slice 26: store keepassxc-browser.
               Slice 37: Veil-branded Chrome / Edge / Firefox extension.
               Later: Mac menu-bar accessory .app (Safari/app fill).
  what         Chrome fill is the extension + host. Safari and native
               Mac apps are an OS credential provider inside that helper.
               No vault window. Menu bar is status, not the SPA.
  when         slice 26, then 32, then 37.

phone
  who          proper iOS/Android app. OS extension + add form.
  what         Add a password. Fill a password. Nothing else.
  when         slices 33–34. after 26.

windows
  who          tray helper. same Go host + Chrome extension.
  what         Revisit WebAuthn plugin / Auto-Type / new APIs on the slice.
  when         slice 35.

linux
  who          tray helper. same Go host + Chrome extension.
  what         Revisit Secret Service / Auto-Type / new APIs on the slice.
  when         slice 36.

glue
  who          identity/glue (seam). clients: glue/kratos, glue/hydra, glue/keto
  what         keto owner/member. hydra first-party + agent clients. invite.
               login is Kratos oauth2_provider, not an HTTP hop in this package.
               Hydra skip_consent still hits urls.consent; glue AcceptConsent is that hop.
               the broker never calls Kratos. written. make glue
  when         with the screens

first-party
client
  who          Hydra admin, once, at identity start
  what         one client for this product. consent skipped. redirect is the broker.
               written. EnsureFirstParty via make glue. make prove-identity
  when         with the glue

broker trusts
Hydra
  who          internal/human. coreos/go-oidc pointed at PWM_HYDRA_ISSUER only
  what         Exchange is PKCE public client. caller gets the id_token, not access/refresh.
               subject is the human. unknown iss rejected before discovery.
               written. make prove-identity exchanges the code
  when         after the client exists

who may
Approve
  who          that Hydra subject
  what         ApproveOIDC verifies the id_token and Approves as that subject.
               planted `self` stays for tests and CLI without --oidc-token-file.
               written. live proof: approval HumanID is the Kratos identity id
  when         last step of the human chain

agent Hydra
client
  who          identity/glue. Hydra admin. CLI `agent hydra` then `agent token`
  what         client_credentials client, jwt access token per client.
               not a Kratos human. subject is the Hydra client id.
               bind issuer+subject to an agent that already exists.
               secret written to --secret-file, never JSON.
               mint is `agent token --secret-file --out-file`. JWT never stdout.
               written. make prove-identity TestLiveAgentClient
  when         after Approve is a Hydra human

laptop
proof
  who          this process, a local unix socket. CLI `serve`
  what         HTTP on pwm.sock. Bearer is the same Hydra JWT as cloud.
               not a new identity. name headers are ignored.
               written. TestLiveLaptopSocket
  when         after the agent Hydra client exists

passkey
  who          this process is the host. CLI `fill`.
               Slice 26: store keepassxc-browser. Slice 37: Veil extension.
  what         native messaging + nacl box. get-logins writes into the page.
               get-totp mints at fill time. the seed never leaves.
               passkeys-get/register not this slice.
               written. TestGetLoginsFillsMatchingURI
  when         after the laptop socket

ssh
  who          golang.org/x/crypto/ssh/agent
  what         the broker signs on a local agent socket. the key never leaves.
               written. CLI `ssh`. SSH_AUTH_SOCK. Add/Remove refused.
               TestSignDoesNotReturnPrivateKey
  when         after fill

env into a child
  who          this process. CLI `run`. Infisical vault run.
  what         granted item material in the child's environment. HTTPS_PROXY stays.
               item name is the env var (uppercased). TOTP minted, seed never in env.
               SSH stays on ssh.sock. Level 1 without approval is skipped, never a prompt.
               written. TestChildEnvInjectsLevel2AndScrubsAudit
  when         after ssh

item keys
  who          x/crypto, the wrap we already use
  what         one key per owner. master key unwraps that. the grant does not get a copy.
               written. TestSQLiteOwnerKeysDifferAndGrantHasNoDEK
               legacy vaults rewrap on open.
  when         after env into a child

org
  who          the owner id we already store
  what         the human's id is the owner of the agent. who may create a grant.
               written. AddGrant denied for another owner. planted `self` is the laptop.
  when         with invites

invites
  who          Kratos. glue IdentityAPI. CLI `human invite EMAIL --code-file`
  what         CreateIdentity + recovery code. Courier delivers. No invite table.
               Email stays in Kratos. organization_id stamped. Keto owner/member
               written by glue. Invite is owner-gated after the first human.
               ApproveOIDC checks Keto, not sqlite.
               written. TestInviteSecondRequiresOwner
  when         second human is real

keto
  who          oryd/keto:v26.2.0. keto-client-go/v26. glue writes. broker reads
               membership through glue.IsMember.
  what         Organization owners and members. Not grants.
               written. TestInviteWritesKetoOwnerAndMember
  when         identity-plane RBAC is real

device
pairing
  who          golang.org/x/crypto/nacl/box. same library as fill.
  what         wrap master to the new machine's public key. device.key + wraps/.
               no plaintext master.key. legacy master.key migrates on Open.
               CLI device new / pubkey / offer / accept. blob is a file.
               copy vault.db yourself. not sync. not a model. not iOS.
               written. TestOfferAcceptOpensSameVaultAndBlobHasNoMaster
  when         second machine is real
```

## Commands

```
make test
make vet
make ci
make identity-up
make glue
make prove-identity
make prove-live
go test ./...
go run ./cmd/password-manager version
```

## Project structure

```
cmd/password-manager    cobra CLI + Streamable HTTP MCP. the broker.
cmd/identity-glue       stdlib. one-shot Hydra first-party client, then consent accept.
identity/               sibling plane. login UI, schema, compose pins
identity/glue            seam. SDKs are in kratos/, hydra/, keto/. invite = both.
identity/glue/kratos     Kratos client. humans, recovery
identity/glue/hydra      Hydra client. tokens, first-party and agent clients
identity/glue/keto       Keto client. owner/member. not grants
internal/app            facade CLI and MCP share
internal/cli            human commands (no --secret on argv)
internal/mcpserver      official Go MCP SDK
internal/proxy          elazarl/goproxy MITM; per-vault CA; fail closed
internal/protocol       the one API
internal/grant          evaluation
internal/broker         the only code that touches secrets. fetch + child env
internal/store          memory + sqlite. owner DEK, master unwraps
internal/crypto         x/crypto wrapper
internal/material       sealed token + TOTP seed; mint at inject; file BLOB
internal/publicapi      OpenAPI HTTP. /v1/items + /v1/use. GET /openapi.json
internal/inject         ${NAME} / pwm:// into a child file. fail closed
internal/passgen        human CLI. crypto/rand. not MCP
internal/human          go-oidc verify Hydra; subject is the human
internal/fill           keepassxc-browser native host. nacl box. not the extension
internal/device         nacl box wrap of master to a second machine
internal/sshagent       x/crypto/ssh/agent. signs. key never leaves
internal/socket         unix HTTP. Bearer JWT. laptop transport
internal/workload       go-oidc verify; issuer+subject → agent
internal/scrub          agent-visible redaction
docs/                   spec + prior art
docs/openapi            the contract. CLI, MCP, SDKs, Blume /reference
sdks/                   generated Go/TS/Python. never handwritten
apps/docs               Blume. /reference consumes the spec
```

Do not scaffold slices 30–36 until 26 is proven. Do not scaffold Native SDK, Tauri, or Electron. The Chrome host is already Go. Windows/Linux fill APIs are reopened on 35–36, not designed now.

## Testing

- `go test ./...` is the in-repo suite. It does not prove Mini origin.
- `make prove-identity` is local Docker Ory. It does not prove `veil.nyc`.
- `make prove-live` is origin truth: `https://veil.nyc` and MCP. It mints a token, fails if GitHub/Linear/Firecrawl/Cloudflare Use is not allow/200, and fails if the secret appears in JSON. `make ci` does not run it.
- `GET /health` is process up. `GET /ready` is Hydra discovery. A green health with a dead issuer is a lie; prove-live checks ready.
- Every Use/Approve path asserts the secret is absent from JSON of the result and of the audit log.
- Prefer httptest and the memory store over mocks.

## Boundaries

- Always: tests before claiming a slice is done; leak assertions on agent-visible types; stdlib or x/crypto for crypto.
- Ask first: new item kinds, new dependencies, changing the grant model.
- Never: return a secret to an agent; add a Reveal API on the agent path; handwrite SDK clients (OpenAPI is the contract); copy Infisical/Bitwarden/Ory source; hand-roll AEAD, TOTP, JWT verification, or an HTTP MITM; compile Kratos or Hydra into the broker; import Ory internals.

## Success criteria (current slice — MeowPass CLI/MCP + sqlite)

- [x] Agent is a principal, not a user with a password.
- [x] Level 2 fetch injects Bearer token; agent result and audit contain no secret.
- [x] Level 1 fetch returns need_approval until a human Approves.
- [x] Fetch to a host not on the item is denied.
- [x] Wrong agent is denied.
- [x] Crypto is x/crypto XChaCha20-Poly1305.
- [x] SQLite persists items; plaintext secret is not on disk.
- [x] CLI: init, item add (secret-file/stdin), agent, grant, use, approve.
- [x] MCP `fetch` / `list_items` over Streamable HTTP. Bearer is the agent. Output JSON has no secret.
- [x] No agent-facing Reveal / `item get` / `--secret` argv.
- [x] HTTPS_PROXY MITM via goproxy; per-vault CA; inject + scrub; unknown hosts denied.
- [x] `run --agent NAME -- CMD` sets HTTP(S)_PROXY and CA env. Granted secrets go into the child. Broker stdout has no secret.
- [x] TOTP seed lives on the item. `pquerna/otp` mints at inject into `X-TOTP`. Seed and code are absent from CLI, MCP, and audit.
- [x] `--totp-file` only. No `--totp` / `--secret` on argv. No `get_totp` tool. `totp enroll --out-file --qr-file` writes the seed and an otpauth PNG. Stdout has neither.
- [x] Workload identity is `coreos/go-oidc` verify only. `agent bind` maps issuer+subject to an existing agent. Unknown issuers are rejected before discovery. No token issuance.
- [x] OAuth refresh uses `golang.org/x/oauth2`. Access token is injected. Refresh token and client secret never appear in agent output.
- [x] Identity plane is pinned Ory images in `identity/`, not source in this tree. Kratos v26.2.0, Hydra v26.2.0, Keto v26.2.0, Postgres. Broker does not talk to Kratos. Broker calls glue for Keto member/owner checks. Grants stay in the vault.
- [x] Glue is `kratos-client-go/v26` + `hydra-client-go/v26` + `keto-client-go/v26`. Login is Kratos `oauth2_provider` accepting Hydra's challenge with the identity id. No session redirects to the screens. Subject is the identity id, never the email. Agent-visible redirect has no session.
- [x] First-party Hydra client is PUT by `make glue`. `skip_consent` is true. Hydra still redirects to glue for consent accept (no screen). Redirect is the broker. `make prove-identity` proves authorize → Kratos → code, no consent screen.
- [x] Broker trusts our Hydra via `internal/human` (`coreos/go-oidc`). Unknown issuers rejected before discovery. `x/oauth2` PKCE exchange returns the id_token only.
- [x] `ApproveOIDC` Approves as that Hydra subject. Membership is Keto via glue. Live: subject and approval HumanID equal the Kratos identity id. Planted `self` stays tests and CLI when Hydra is not configured. If the issuer is set, `Approve` without a token fails.
- [x] Agent that does not speak OIDC is a Hydra `client_credentials` client (`access_token_strategy=jwt`), not a Kratos human. Glue creates it. `agent hydra` binds issuer+subject. Secret is `--secret-file` only. Live: JWT verifies to that agent via go-oidc.
- [x] Laptop socket is unix HTTP (`pwm.sock`). Bearer is that same JWT. Name is not identity. Live: Hydra JWT over the socket Uses as that agent. Secret absent from the response.
- [x] Fill host speaks native messaging (`nacl/box`). `get-logins` returns the password to the extension only. `FillEntry.Login` is the sealed username, not `item.Name`. Empty login is honest. Agent list/MCP JSON has no secret and no login. `fill install` writes the native host manifest, not the extension. Product chrome is slice 37. `passkeys-*` is not this slice. Touch ID at fill is still open.
- [x] SSH agent is `golang.org/x/crypto/ssh/agent` on a local unix socket (`ssh.sock`). The broker signs. List/JSON has no PEM. `Add`/`Remove` refused. CLI `item add --ssh-file` never argv.
- [x] Env into a child is Infisical `vault run`. `password-manager run` sets granted secrets in the child env and keeps `HTTPS_PROXY`. Broker stdout, MCP, and audit have no secret. Level 1 is skipped, never a prompt. SSH is not injected.
- [x] Owner-key wrap: one DEK per owner, sealed with master via x/crypto. Grants and agent JSON have no key. Legacy secrets sealed with master rewrap on open.
- [x] Device pairing: nacl box wrap of master to a second device public key. `device.key` + `wraps/`. No plaintext `master.key`. Blob and CLI JSON have no master. Copy vault.db; not sync; not a model; not iOS.
- [x] Org: agent owner is the human id. Who may create a grant is that owner. Planted `self` stays the laptop stand-in.
- [x] One org id: `protocol.LocalOrgID` is the vault OrgID, Kratos `organization_id`, and the Keto object. A second company is not this product yet.
- [x] Invites are Kratos: glue `CreateIdentity` + `CreateRecoveryCodeForIdentity`. CLI `human invite --code-file`. Owner-gated after bootstrap (`--oidc-token-file` / `PWM_HUMAN_TOKEN`). Email and recovery code never enter sqlite. ApproveOIDC requires Keto membership. organization_id is stamped. Keto owner/member is written by glue.
- [x] Remote MCP is Streamable HTTP. Bearer is Hydra JWT / bound OIDC. `mcp config` prints url+header template, never the token. RFC 9728 metadata points at Hydra. Cloud agents fetch that URL. JSON has no secret. No bearer is 401. Cursor (no env interpolation) uses `mcp stdio` / `mcp laptop` against origin HTTP. Token file, never mcp.json. Laptop remints a stale JWT with `client_credentials` (`PWM_HYDRA_SECRET_FILE`). Agent clients stay `client_credentials` only. Not `@ory/mcp-oauth-provider`. Not auth-code as the human.
- [x] Cloud MCP is `https://veil.nyc/mcp`. Railway origin. Cloudflare DNS only, not Tunnel, not Workers. `GET /health` is 200. No bearer on `/mcp` is 401. Flue, Codex, and Cloudflare Agents are principals; Bearer is still the agent.
- [x] Hydra public mint is `https://id.veil.nyc` (token, JWKS, discovery). Not admin `:4445`. Not Kratos. Issuer in the JWT matches. RFC 9728 points there. Cloud agents `client_credentials` then Bearer to `/mcp`. Secret never in MCP JSON.
- [x] Origin is the Mac Mini. Hydra and the broker run there. Cloudflare Tunnel points at that machine. The laptop is not a second public Hydra.
- [x] Secret refs `${NAME}` and `pwm://name` resolve only in `run --inject` (and env). Unknown refs fail closed. Broker stdout has no secret.
- [x] Item update, archive, delete, tags, extra URIs. Archived items are hidden from Use, list, fill, MCP. History is `item_versions` (sealed). Restore copies the sealed blob.
- [x] File items are a sealed BLOB. Owner `item write --out-file`. Not MCP. Not child env.
- [x] Grant expiry is `Grant.ExpiresAt` (`grant add --expires`). Zero is forever. Not a second share type.
- [x] Owner `audit` lists events. No secret in JSON. Not an MCP tool. Origin `GET /v1/events` is this agent's events. `PWM_ORIGIN` makes CLI `use`/`audit` the same HTTP contract as the SDK.
- [x] `gen` is human CLI `crypto/rand`. `--out-file` or stdout. Not MCP. Not a vault item until `item add`.
- [x] No vaults. No 1Password Connect/op/import. No scoped Connect-style token. MCP stays `list_items` + `fetch`.
- [x] OpenAPI is the contract (`docs/openapi/password-manager.openapi.json`). `POST /v1/use` takes method, headers, body. CLI `--body-file`. MCP `fetch` the same. Generated TS/Python/Go SDKs. Blume `/reference`. No GetSecret on any generated surface.
- [x] `agent token --secret-file --out-file` mints a Hydra JWT to disk. Never stdout. Same `client_credentials` as cloud agents. Live proof is Bearer `POST /v1/use`.
- [x] Laptop MCP is `mcp stdio` against origin HTTP. Cursor live: `list_items` then `fetch` GitHub `/user` → allow, 200, token absent from the tool payload. GUI hosts do not interpolate `${file:}`. Token file + remint paths, never the JWT in MCP JSON.
- [x] One store. `PWM_ORIGIN` makes CLI `item` / `grant` / `list` / `fill` origin HTTP. `openApp` refuses a second sqlite. Bearer is agent or Keto member human. Owner `POST /v1/items` may send the secret; responses, MCP, and generated SDKs never include it. `POST /v1/fill/logins` is the native-host path only.
- [x] `human login --out-file` mints a Hydra ID token to disk. PKCE. Never stdout. Owner CLI and fill use `PWM_HUMAN_TOKEN_FILE`, not the agent JWT.
- [x] Identity on origin. Sibling Railway services: official Kratos, Keto, glue, Hydra. Login UI is Cloudflare Workers (`veil-login`) at `https://login.veil.nyc`. Kratos public is `https://accounts.veil.nyc`. Glue consent is `https://consent.veil.nyc`. Hydra first-party client `password-manager`. Live human mint against `https://id.veil.nyc`. Grants stay in the vault.

## Use what exists. Do not rewrite it.

| Need | Library or product | Do not |
|---|---|---|
| Human directory, invites, sessions, tokens | Pinned Ory Kratos + Hydra | Zitadel, Better Auth, forking Ory, Oathkeeper, a sqlite user table |
| Identity-plane owner / member | Pinned Ory Keto v26.2.0 | sqlite roles. Putting grants in Keto |
| Who may Use this item | the grant | Org RBAC, Better Auth, Keto |
| OIDC verify | `coreos/go-oidc` | Parse JWTs ourselves |
| OAuth refresh | `golang.org/x/oauth2` | A token client |
| TOTP | `pquerna/otp` | RFC 6238 by hand |
| Passkeys, we are the site | `go-webauthn/webauthn` or Kratos | A custom ceremony. Using it to fill Stripe. |
| Fill in a browser | Veil extension (37) + Go host. Slice 26 proves the wire with store keepassxc-browser. | Copying keepassxc-browser into this tree (GPL-3). KeePassXC as the vault. A desktop app as the fill host. |
| Human vault UI | the SPA (Cloudflare). every option except add+fill on the phone | Native SDK. Tauri. Electron. A second Mac vault. Phone admin. |
| Phone | add a password, fill a password (slices 33–34) | Grants, agents, audit, SSH, settings, embedding the SPA |
| Mac helper | menu-bar accessory + ASCredentialProvider (slice 32) | A vault window. Using it to fill Chrome. |
| Windows / Linux helper | tray + Chrome extension. Revisit OS APIs on slices 35–36 | Inventing an Autofill API. Shipping Auto-Type before 26. |
| Identity screens | Ory Elements in identity/login | Restyling Elements. Putting them in the broker. |
| Vault UI widgets | shadcn from Core. Uniwind if a phone WebView/RN shell exists later | NativeWind. One component file in Swift. Native SDK as the UI. |
| Device pairing | `golang.org/x/crypto/nacl/box` | Age, a second vault, pairing a model, iOS |
| MITM | `elazarl/goproxy` | A CONNECT parser |
| AEAD | `x/crypto` | A cipher |

## Open questions

None on the enemy. 1Password. Individual / Families / Teams / startup <100, plus the agents those people already run. Enterprise 1Password is not this product.

Windows and Linux password-into-an-app fill: no Apple-style API as of 2026-09-10 (passkeys plugin / Secret Service / Auto-Type). Reopen on slices 35 and 36. Do not reopen now.

Product is Veil. Repo/CLI stay `password-manager`.
