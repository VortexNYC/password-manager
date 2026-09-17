# Veil SDK factory

Same shape as Payments. Do not handwrite language clients.

## Source of truth

- OpenAPI contract: `docs/openapi/veil.openapi.json`
- Embedded copy served at `GET /openapi.json`: `internal/publicapi/spec.json`
- Generator: `pnpm run sdk:generate`
- Docs site: `pnpm --filter @vortex-api/veil-docs dev` — Blume `/reference` consumes the spec

## SDK outputs

| Language   | Output            | Generator         | Package                    |
| ---------- | ----------------- | ----------------- | -------------------------- |
| TypeScript | `sdks/typescript`  | `@hey-api/openapi-ts` | `@vortex-api/veil`   |
| Python     | `sdks/python`     | OpenAPI Generator | `vortex-api-veil`           |
| Go         | `sdks/go`         | OpenAPI Generator | `github.com/VortexNYC/veil/sdks/go` |

## Rules

- `pnpm run sdk:generate` after any spec change. It copies the spec into the Go embed. Python/Go need `java` or Docker (`openapitools/openapi-generator-cli:v7.23.0`).
- There is no `GetSecret`. `useItem` injects. `listItems` is metadata.
- CLI `use --body-file` / MCP `fetch` / `POST /v1/use` are the same operation. Proof: `pnpm run prove:cli-golden-flow`.
- Generated SDKs are MIT. This repo stays the product.

## Publishing

Public product SDKs live under the `@vortex-api` npm org (public npmjs) and the `vortex-api-veil` PyPI project. Internal platform packages stay under `@vortexnyc/*` on GitHub Packages — SDKs are public, so they do not go there.

| SDK | Publish |
| --- | --- |
| `@vortex-api/veil` | `cd sdks/typescript && npm publish --access public` — account 2FA needs `--otp` or an automation token |
| `vortex-api-veil` | `cd sdks/python && uv build && uv publish --token "$UV_PUBLISH_TOKEN"` — first publish needs an account-scoped token (project-scoped only works after the project exists) |
| `sdks/go` | No registry. Tag the merge commit `sdks/go/vX.Y.Z`; `go get` resolves it via proxy.golang.org. |
