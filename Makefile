.PHONY: all build build-gateway build-router build-control build-ui test demo demo-router kill clean

all: build

# ---------------------------------------------------------------------------
# Build
# ---------------------------------------------------------------------------

build: build-gateway build-router build-control build-ui

build-gateway:
	@mkdir -p bin
	go build -o ./bin/flint-gateway ./cmd/gateway

build-router:
	@mkdir -p bin
	go build -o ./bin/flint-router ./cmd/router

build-control:
	@mkdir -p bin
	go build -o ./bin/flint-control ./cmd/control

build-ui:
	cd ui && npm install && npm run build

# ---------------------------------------------------------------------------
# Test
# ---------------------------------------------------------------------------

test:
	go test ./... -race -count=1

test-engine:
	go test ./engine/... -race -count=1

# ---------------------------------------------------------------------------
# Demo
# ---------------------------------------------------------------------------

demo: build-gateway build-control
	@./scripts/demo.sh

# Run the demo using the UI dev server (Vite) — UI prebuild not required.
demo-dev: build-gateway build-control
	@./scripts/demo.sh

demo-router: build-router build-control
	@./scripts/router-demo.sh

kill:
	-pkill -f flint-gateway 2>/dev/null
	-pkill -f flint-router 2>/dev/null
	-pkill -f flint-control 2>/dev/null
	-pkill -f "vite" 2>/dev/null
	@echo "[make kill] stopped local Flint processes"

# ---------------------------------------------------------------------------
# Clean
# ---------------------------------------------------------------------------

clean:
	rm -rf bin
	rm -f flint-audit.jsonl router-audit.jsonl
	rm -f .demo-control.log .demo-gateway.log .demo-router.log .demo-ui.log

clean-ui:
	rm -rf ui/node_modules ui/dist
