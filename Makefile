VERSION ?= 0.1.1
LDFLAGS := -s -w -X main.version=$(VERSION)

.PHONY: build test clean

build:
	mkdir -p dist
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags "$(LDFLAGS)" -o dist/guest-accounts-linux-amd64 .
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -ldflags "$(LDFLAGS)" -o dist/guest-accounts-linux-arm64 .

test:
	go vet ./...
	go test -race -count=1 ./...

clean:
	rm -rf dist
