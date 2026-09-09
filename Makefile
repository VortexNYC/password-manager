.PHONY: test vet fmt tidy ci

test:
	go test ./...

vet:
	go vet ./...

fmt:
	gofmt -w .

tidy:
	go mod tidy

ci: vet test
