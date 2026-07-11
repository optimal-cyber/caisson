# Caisson — local dev shortcuts
BIN := caisson
PORT ?= 8000

.PHONY: help build run demo demo-pull test vet fmt tidy site clean

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
	  awk 'BEGIN{FS=":.*?## "}{printf "  \033[36m%-10s\033[0m %s\n", $$1, $$2}'

build: ## Build the caisson binary
	go build -o $(BIN) .

run: build ## Build, then run with no args (prints the vault banner)
	./$(BIN)

demo: build ## Generate a key, sign+pack the sample app, verify, and read it back
	@echo "== key gen ==" && ./$(BIN) key gen --out caisson-demo
	@echo "\n== init (scaffold a caisson.yaml) ==" && rm -rf .demo-init && mkdir -p .demo-init && (cd .demo-init && ../$(BIN) init --name demo-svc) && echo "\n--- generated caisson.yaml ---" && cat .demo-init/caisson.yaml && rm -rf .demo-init
	@echo "\n== package create (reads examples/hello-app/caisson.yaml; --key overrides it) ==" && ./$(BIN) package create ./examples/hello-app --key caisson-demo.key --scan-report examples/hello-app-scan.grype.json
	@echo "\n== verify (seal + signature + SLSA provenance) ==" && ./$(BIN) verify hello-app.caisson --key caisson-demo.pub
	@echo "\n== package inspect ==" && ./$(BIN) package inspect hello-app.caisson
	@echo "\n== sbom view (real CycloneDX) ==" && ./$(BIN) sbom view hello-app.caisson
	@echo "\n== sbom export ==" && ./$(BIN) sbom export hello-app.caisson --out ./evidence
	@echo "\n== deploy (policy gate: no criticals) ==" && ./$(BIN) deploy hello-app.caisson --deny-severity critical --require-signature --evidence-export
	@echo "\n== evidence export ==" && ./$(BIN) evidence export hello-app.caisson --out ./evidence
	@echo "\n== attest export (cosign-compatible DSSE) ==" && ./$(BIN) attest export hello-app.caisson --out ./evidence
	@echo "\n== attest verify (offline, no cosign) ==" && ./$(BIN) attest verify ./evidence/hello-app/provenance.dsse.json --key caisson-demo.pub

demo-pull: build ## Like demo, but ALSO pulls declared images into a sealed OCI layout (needs a reachable registry + creds)
	@echo "== key gen ==" && ./$(BIN) key gen --out caisson-demo
	@echo "\n== package create --pull-images (real image pulls; needs registry access) ==" && ./$(BIN) package create ./examples/hello-app --key caisson-demo.key --scan-report examples/hello-app-scan.grype.json --pull-images
	@echo "\n== verify (seal now also covers the embedded OCI layout) ==" && ./$(BIN) verify hello-app.caisson --key caisson-demo.pub
	@echo "\n== package inspect ==" && ./$(BIN) package inspect hello-app.caisson

test: ## Run the Go tests
	go test ./...

vet: ## go vet
	go vet ./...

fmt: ## Format all Go files
	gofmt -w .

tidy: ## Sync go.mod/go.sum
	go mod tidy

site: ## Serve the landing page at http://localhost:$(PORT)
	@echo "Serving web/ at http://localhost:$(PORT)  (Ctrl-C to stop)"
	cd web && python3 -m http.server $(PORT)

clean: ## Remove build artifacts, generated vaults, keys, and evidence
	rm -f $(BIN)
	rm -f *.caisson
	rm -f *.key *.pub
	rm -rf ./evidence
	rm -rf .demo-init
