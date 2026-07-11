# Caisson — local dev shortcuts
BIN := caisson
PORT ?= 8000

.PHONY: help build run demo test vet fmt tidy site clean

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
	  awk 'BEGIN{FS=":.*?## "}{printf "  \033[36m%-10s\033[0m %s\n", $$1, $$2}'

build: ## Build the caisson binary
	go build -o $(BIN) .

run: build ## Build, then run with no args (prints the vault banner)
	./$(BIN)

demo: build ## Generate a key, sign+pack the sample app, verify, and read it back
	@echo "== key gen ==" && ./$(BIN) key gen --out caisson-demo
	@echo "\n== package create (signed) ==" && ./$(BIN) package create ./examples/hello-app --version 1.0.0 --key caisson-demo.key
	@echo "\n== verify (seal + signature + SLSA provenance) ==" && ./$(BIN) verify hello-app.caisson --key caisson-demo.pub
	@echo "\n== package inspect ==" && ./$(BIN) package inspect hello-app.caisson
	@echo "\n== sbom view =="       && ./$(BIN) sbom view hello-app.caisson
	@echo "\n== deploy ==" && ./$(BIN) deploy hello-app.caisson --evidence-export
	@echo "\n== evidence export ==" && ./$(BIN) evidence export hello-app.caisson --out ./evidence

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
