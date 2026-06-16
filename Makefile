# WasmForge Makefile
# Ensures build_assets.tar.gz is regenerated before compiling.

.DELETE_ON_ERROR:

BINARY    := wasmforge
ASSETS    := internal/build/build_assets.tar.gz
ASSET_SRC := internal/hostmod internal/runtime internal/names wazero

# Source files that feed into the archive.
ASSET_DEPS := $(shell find $(ASSET_SRC) \( -name '*.go' -not -name '*_test.go' \) -o -name '*.s' -o -name 'go.mod' -o -name 'go.sum' 2>/dev/null)

# Docker build environment for .NET (NativeAOT-WASI) targets — see
# Dockerfile.build for details.
DOCKER_IMAGE     := wasmforge/build:latest
DOCKER_OUT_DIR   ?= $(CURDIR)/out
DOCKER_SRC       ?=
DOCKER_PROJECT   ?= seatbelt

.PHONY: all build clean generate docker-build docker-run test-parity-seatbelt test-parity-rubeus test-parity-sharpdpapi test-parity-certify test-parity-sharpup test-parity-sharpview test-parity-all verify-ast-equivalence

all: build

# Regenerate build assets archive when source files change.
$(ASSETS): $(ASSET_DEPS)
	GOWORK=off go run ./cmd/gen-build-assets

generate: $(ASSETS)

# Build wasmforge binary, regenerating assets if stale.
build: $(ASSETS)
	GOWORK=off go build -trimpath -o $(BINARY) ./cmd/wasmforge

clean:
	rm -f $(BINARY) $(ASSETS)
	rm -rf ~/.wasmforge/cache/

# ── Docker build environment ────────────────────────────────────────────
# Builds the wasmforge/build image used for .NET (NativeAOT-WASI) targets.
# The image bundles Go 1.25.3, .NET SDK 10, WASI SDK 24, and the
# wasm-component-ld bypass wrapper required by our env imports.
docker-build:
	docker build -f Dockerfile.build -t $(DOCKER_IMAGE) .

# Forge a .NET project as a Windows PE via the Docker image. Mount this
# wasmforge source tree as /wasmforge and the target project as /src.
#
# Example:
#   make docker-run DOCKER_SRC=/tmp/seatbelt-fresh DOCKER_PROJECT=seatbelt
#   → out/seatbelt.exe
#
# DOCKER_SRC defaults to the seatbelt-fresh dir in /tmp (the canonical
# upstream Seatbelt source tree we ship through).
docker-run:
	@if [ -z "$(DOCKER_SRC)" ]; then \
		echo "ERROR: DOCKER_SRC must be set, e.g. DOCKER_SRC=/tmp/seatbelt-fresh"; \
		echo "       (the path to the .NET project source tree on the host)"; \
		exit 2; \
	fi
	@mkdir -p $(DOCKER_OUT_DIR)
	docker run --rm \
		-v "$(CURDIR):/wasmforge:ro" \
		-v "$(DOCKER_SRC):/src:ro" \
		-v "$(DOCKER_OUT_DIR):/out" \
		$(DOCKER_IMAGE) $(DOCKER_PROJECT)

# ── Parity test harness ─────────────────────────────────────────────────
# Per-tool parity sweep: pushes the built .exe to the Win11 lab, runs each
# command listed in test/parity/<tool>/, normalizes the output, and diffs
# against the committed golden baselines under testdata/parity-baselines/.
#
# WASMFORGE_TEST_BINARY can override the default binary path.
# Tests SKIP cleanly when the lab is unreachable (not FAIL).
#
# GOWORK=off because test/ is a separate Go module (github.com/praetorian-inc/wftest)
# that is intentionally not in the parent go.work use directive.
test-parity-seatbelt:
	cd test && \
	WASMFORGE_TEST_BINARY=$${WASMFORGE_TEST_BINARY:-$(DOCKER_OUT_DIR)/seatbelt.exe} \
	GOWORK=off go test -tags parity ./parity/seatbelt/ -v

# Per-tool parity sweep for Rubeus. Same structure as Seatbelt.
test-parity-rubeus:
	cd test && \
	WASMFORGE_TEST_BINARY=$${WASMFORGE_TEST_BINARY:-$(DOCKER_OUT_DIR)/rubeus.exe} \
	GOWORK=off go test -tags parity ./parity/rubeus/ -v

test-parity-sharpdpapi:
	cd test && \
	WASMFORGE_TEST_BINARY=$${WASMFORGE_TEST_BINARY:-$(DOCKER_OUT_DIR)/sharpdpapi.exe} \
	GOWORK=off go test -tags parity ./parity/sharpdpapi/ -v

test-parity-certify:
	cd test && \
	WASMFORGE_TEST_BINARY=$${WASMFORGE_TEST_BINARY:-$(DOCKER_OUT_DIR)/certify.exe} \
	GOWORK=off go test -tags parity ./parity/certify/ -v

test-parity-sharpup:
	cd test && \
	WASMFORGE_TEST_BINARY=$${WASMFORGE_TEST_BINARY:-$(DOCKER_OUT_DIR)/sharpup.exe} \
	GOWORK=off go test -tags parity ./parity/sharpup/ -v

test-parity-sharpview:
	cd test && \
	WASMFORGE_TEST_BINARY=$${WASMFORGE_TEST_BINARY:-$(DOCKER_OUT_DIR)/sharpview.exe} \
	GOWORK=off go test -tags parity ./parity/sharpview/ -v

# Aggregate parity target — runs all 6 tool sweeps.
test-parity-all: test-parity-seatbelt test-parity-rubeus test-parity-sharpdpapi test-parity-certify test-parity-sharpup test-parity-sharpview

# ── AST patcher equivalence verification ────────────────────────────────────
# Verify that the AST patcher produces byte-identical output to the legacy text
# patcher for every .cs file it touches. Use this to gate B.2+ rule migrations.
#
# Usage: make verify-ast-equivalence SRC=/tmp/seatbelt-fresh
#
verify-ast-equivalence:
	@if [ -z "$(SRC)" ]; then echo "ERROR: SRC must be set, e.g. SRC=/tmp/seatbelt-fresh"; exit 2; fi
	@rm -rf /tmp/wasmforge-ast-verify
	@cp -r $(SRC) /tmp/wasmforge-ast-verify
	GOWORK=off go run ./cmd/wasmforge dotnet-patch --ast-verify /tmp/wasmforge-ast-verify
