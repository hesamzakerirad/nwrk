PKG     := github.com/radestsam/nwrk
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null | sed 's/^v//')
COMMIT  ?= $(shell git rev-parse --short HEAD 2>/dev/null)
DATE    ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS := -s -w \
	-X $(PKG)/internal/buildinfo.Version=$(VERSION) \
	-X $(PKG)/internal/buildinfo.Commit=$(COMMIT) \
	-X $(PKG)/internal/buildinfo.Date=$(DATE)

.PHONY: build test fuzz lint fmt site clean docker-test docker-build docker-lint

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
	hugo --minify --source site

clean:
	rm -rf bin dist site/public site/resources

# Docker toolchain. The host needs Docker only: no local Go install.
# Module and build caches live in named volumes, so repeat runs are fast.
GO_IMAGE ?= golang:1.26
DOCKER_GO = docker run --rm \
	-v "$(CURDIR)":/src -w /src \
	-v nwrk-go-mod:/go/pkg/mod -v nwrk-go-build:/root/.cache/go-build \
	$(GO_IMAGE)

docker-test:
	$(DOCKER_GO) go test -race ./...

docker-lint:
	$(DOCKER_GO) sh -c 'test -z "$$(gofmt -l .)" || { echo "gofmt needed:"; gofmt -l .; exit 1; }; go vet ./... && go run honnef.co/go/tools/cmd/staticcheck@2026.2.2 ./...'

# Builds native binaries for the supported systems into bin/.
docker-build:
	$(DOCKER_GO) sh -c 'for t in linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64; do \
		GOOS=$${t%/*} GOARCH=$${t#*/} CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" \
			-o bin/nw-$${t%/*}-$${t#*/}$$([ $${t%/*} = windows ] && echo .exe) ./cmd/nw || exit 1; done'
