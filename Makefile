VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X github.com/arngory/cii/internal/version.Version=$(VERSION)
GOFLAGS := -trimpath
export CGO_ENABLED := 0

PLATFORMS := \
	linux/amd64 linux/arm64 linux/arm/7 linux/386 \
	linux/mips/softfloat linux/mipsle/softfloat linux/riscv64 \
	darwin/amd64 darwin/arm64 \
	windows/amd64 windows/arm64

.PHONY: build test vet fmt-check check cross schema fuzz

build:
	go build $(GOFLAGS) -ldflags '$(LDFLAGS)' -o cii ./cmd/cii

test:
	go test ./...

vet:
	go vet ./...

fmt-check:
	@test -z "$$(gofmt -l .)" || { gofmt -l .; exit 1; }

check: fmt-check vet test

cross:
	@mkdir -p dist
	@set -e; for p in $(PLATFORMS); do \
		os=$${p%%/*}; rest=$${p#*/}; arch=$${rest%%/*}; var=$${rest#*/}; [ "$$var" = "$$rest" ] && var=; \
		name=cii-$$os-$$arch$${var:+-$$var}; [ $$os = windows ] && name=$$name.exe; \
		goarm=; gomips=; \
		case $$arch in arm) goarm=$$var;; mips|mipsle) gomips=$$var;; esac; \
		echo "build $$name"; \
		GOOS=$$os GOARCH=$$arch GOARM=$$goarm GOMIPS=$$gomips go build $(GOFLAGS) -ldflags '$(LDFLAGS)' -o dist/$$name ./cmd/cii; \
	done
	@cd dist && sha256sum cii-* > SHA256SUMS

schema:
	go run ./tools/genschema

FUZZTIME ?= 30s

fuzz:
	go test ./internal/probe/ -run '^$$' -fuzz '^FuzzEvals$$' -fuzztime $(FUZZTIME)
	go test ./internal/risk/ -run '^$$' -fuzz '^FuzzDataParsers$$' -fuzztime $(FUZZTIME)
	go test ./internal/bench/ -run '^$$' -fuzz '^FuzzParseFio$$' -fuzztime $(FUZZTIME)
	go test ./internal/censor/ -run '^$$' -fuzz '^FuzzParseAnswer$$' -fuzztime $(FUZZTIME)
