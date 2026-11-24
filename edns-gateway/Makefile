BINARY   := edns-gateway
PKG      := github.com/enterprise/edns-gateway
GOFLAGS  := -trimpath
LDFLAGS  := -s -w

.PHONY: all build test race vet fmt lint clean cert

all: build

build:
	go build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o bin/$(BINARY) ./cmd/edns-gateway

test:
	go test ./... -timeout 120s

race:
	go test -race ./... -timeout 180s

vet:
	go vet ./...

fmt:
	gofmt -s -w .

lint: vet
	@command -v staticcheck >/dev/null 2>&1 && staticcheck ./... || echo "staticcheck 未安装，跳过"

clean:
	rm -rf bin/

cert:
	go run ./cmd/edns-gateway cert -out certs/
