BINARY := reconductor
PKG := ./cmd/reconductor

.PHONY: all build test race cover vet fmt fmt-check clean install

all: fmt-check vet build test

build:
	go build -o $(BINARY) $(PKG)

test:
	go test ./...

race:
	go test -race ./...

cover:
	go test -cover ./...

vet:
	go vet ./...

fmt:
	gofmt -w .

fmt-check:
	@test -z "$$(gofmt -l .)" || (echo "gofmt needed:"; gofmt -l .; exit 1)

install:
	go install $(PKG)

clean:
	rm -rf $(BINARY) recon_*
