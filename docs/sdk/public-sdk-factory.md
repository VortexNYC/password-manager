# Vortex Password Manager SDK factory

Same shape as Payments. Do not handwrite language clients.

## Source of truth

- OpenAPI contract: `docs/openapi/password-manager.openapi.json`
- Embedded copy served at `GET /openapi.json`: `internal/publicapi/spec.json`
- Generator: `pnpm run sdk:generate`
- Docs site: `pnpm --filter @vortexnyc/pwm-docs dev` — Blume `/reference` consumes the spec

## SDK outputs

| Language   | Output            | Generator         | Package                    |
| ---------- | ----------------- | ----------------- | -------------------------- |
| TypeScript | `sdks/typescript`  | `@hey-api/openapi-ts` | `@vortex-api/pwm-sdk`   |
| Python     | `sdks/python`     | OpenAPI Generator | `vortex-pwm-sdk`           |
| Go         | `sdks/go`         | OpenAPI Generator | `github.com/vortexnyc/pwm-go` |

## Rules

- `pnpm run sdk:generate` after any spec change. It copies the spec into the Go embed. Python/Go need `java` or Docker (`openapitools/openapi-generator-cli:v7.23.0`).
- There is no `GetSecret`. `useItem` injects. `listItems` is metadata.
- CLI `use --body-file` / MCP `fetch` / `POST /v1/use` are the same operation. Proof: `pnpm run prove:cli-golden-flow`.
- Generated SDKs are MIT. This repo stays the product.
