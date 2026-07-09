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

demo: build ## Pack the sample app into a real vault, then read it back
	@echo "== package create (writes a real hello-app.caisson) ==" && ./$(BIN) package create ./examples/hello-app --version 1.0.0
	@echo "\n== package inspect ==" && ./$(BIN) package inspect hello-app.caisson
	@echo "\n== sbom view =="       && ./$(BIN) sbom view hello-app.caisson
	@echo "\n== deploy (real seal verification) ==" && ./$(BIN) deploy hello-app.caisson --evidence-export
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

clean: ## Remove build artifacts and generated vaults
	rm -f $(BIN)
	rm -f *.caisson
	rm -rf ./evidence
