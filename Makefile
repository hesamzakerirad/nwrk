PKG     := github.com/hesamzakerirad/nwrk
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null | sed 's/^v//')
COMMIT  ?= $(shell git rev-parse --short HEAD 2>/dev/null)
DATE    ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS := -s -w \
	-X $(PKG)/internal/buildinfo.Version=$(VERSION) \
	-X $(PKG)/internal/buildinfo.Commit=$(COMMIT) \
	-X $(PKG)/internal/buildinfo.Date=$(DATE)

.PHONY: build test fuzz lint fmt site clean

build:
	go build -trimpath -ldflags '$(LDFLAGS)' -o bin/nw ./cmd/nw

test:
	go test -race ./...

# FUZZTIME bounds each fuzz target; CI uses a short run, raise it locally.
FUZZTIME ?= 10s
fuzz:
	@for f in FuzzHost FuzzHostPort FuzzURL FuzzResolver; do \
		go test ./internal/target -run '^$$' -fuzz "^$$f\$$" -fuzztime $(FUZZTIME) -parallel 2 || exit 1; \
	done

lint:
	@test -z "$$(gofmt -l .)" || { echo "gofmt needed:"; gofmt -l .; exit 1; }
	go vet ./...
	go run honnef.co/go/tools/cmd/staticcheck@2026.2.2 ./...

fmt:
	gofmt -w .

site:
	./scripts/translation-status.sh
	hugo --minify --source site

clean:
	rm -rf bin dist site/public site/resources
