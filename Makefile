.PHONY: test vet fmt tidy sdk-fresh ci build identity-config identity-env identity-up glue prove-identity prove-cli-golden-flow prove-live prove-fill loadtest

test:
	env -u PWM_HYDRA_ISSUER -u PWM_HYDRA_ADMIN -u PWM_HOME -u PWM_OIDC_TOKEN -u PWM_ORIGIN -u PWM_OIDC_TOKEN_FILE -u PWM_HYDRA_SECRET_FILE -u PWM_AGENT PWM_FILL_TOUCHID=0 go test -race -shuffle=on -timeout 15m ./...

vet:
	go vet ./...

fmt:
	gofmt -w .

tidy:
	go mod tidy

build:
	go build -o bin/password-manager ./cmd/password-manager

sdk-fresh:
	pnpm run sdk:generate
	@if [ -n "$$(git status --porcelain -- sdks internal/publicapi/spec.json)" ]; then \
		echo "sdk:generate dirtied committed SDKs. Commit the generator output or revert the OpenAPI change."; \
		git status -- sdks internal/publicapi/spec.json; \
		git diff -- sdks internal/publicapi/spec.json; \
		exit 1; \
	fi

ci:
	$(MAKE) sdk-fresh
	$(MAKE) vet test
	pnpm exec vp lint
	pnpm run typecheck
	pnpm --filter veil-vault test
	pnpm run docs:build

prove-cli-golden-flow:
	go test ./internal/cli ./internal/mcpserver ./internal/publicapi -count=1

identity-config:
	docker compose --env-file identity/.env -f identity/compose.yml config

identity-env:
	@test -f identity/.env || { \
		printf '%s\n' \
			"POSTGRES_PASSWORD=$$(openssl rand -hex 24)" \
			"KRATOS_COOKIE_SECRET=$$(openssl rand -hex 24)" \
			"KRATOS_CIPHER_SECRET=$$(openssl rand -hex 16)" \
			"HYDRA_SYSTEM_SECRET=$$(openssl rand -hex 24)" \
			"HYDRA_PAIRWISE_SALT=$$(openssl rand -hex 24)" \
			"HYDRA_CLIENT_ID=password-manager" \
			"BROKER_REDIRECT_URL=http://127.0.0.1:4460/oidc/callback" \
			"URLS_SELF_ISSUER=http://127.0.0.1:4444" \
			> identity/.env; \
	}

identity-up: identity-env
	docker compose --env-file identity/.env -f identity/compose.yml up -d

prove-identity: identity-up
	go test -tags live ./identity/glue -count=1 -timeout 3m

prove-live:
	./scripts/prove-live.sh

prove-fill:
	./scripts/prove-fill.sh

login:
	pnpm --filter identity-login dev

glue:
	go run ./cmd/identity-glue

loadtest:
	@if ! command -v k6 >/dev/null 2>&1; then \
		echo "k6 not installed. Install from https://grafana.com/docs/k6/latest/set-up/install-k6/"; \
		exit 1; \
	fi
	@test -n "$$VEIL_AGENT_TOKEN" || { echo "VEIL_AGENT_TOKEN is required"; exit 1; }
	@test -n "$$VEIL_ITEM_ID" || { echo "VEIL_ITEM_ID is required"; exit 1; }
	k6 run tests/load/k6/use.js
