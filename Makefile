.PHONY: build test lint release fetch-data demo

build:
	go build -ldflags "-s -w -X main.version=$$(git describe --tags --always --dirty 2>/dev/null || echo dev)" -o sudocheck .

test:
	GOCACHE=$${GOCACHE:-/tmp/sudocheck-go-build} go test ./...

lint:
	go vet ./...

fetch-data:
	go run scripts/fetch_gtfobins.go

demo:
	go run . demo --no-color

release:
	goreleaser release --clean

