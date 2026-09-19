# CGO_ENABLED=0 keeps the binary static: the same file is copied into the
# installer ISO and must run there.
dryserver: $(shell find cmd internal assets -type f) go.mod go.sum
	CGO_ENABLED=0 go build -o $@ ./cmd/dryserver

.PHONY: test
test:
	go test ./cmd/... ./internal/... ./assets/...
