.PHONY: test vet fmt tidy ci build

test:
	go test ./...

vet:
	go vet ./...

fmt:
	gofmt -w .

tidy:
	go mod tidy

build:
	go build -o bin/password-manager ./cmd/password-manager

ci: vet test
