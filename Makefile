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

demo: build ## Run every stub command end-to-end
	@echo "== init =="        && ./$(BIN) init
	@echo "\n== package create ==" && ./$(BIN) package create ./my-app
	@echo "\n== package inspect ==" && ./$(BIN) package inspect my-app.caisson
	@echo "\n== sbom view =="       && ./$(BIN) sbom view my-app.caisson
	@echo "\n== evidence export ==" && ./$(BIN) evidence export my-app.caisson --out ./evidence
	@echo "\n== deploy =="          && ./$(BIN) deploy my-app.caisson --evidence-export

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

clean: ## Remove build artifacts
	rm -f $(BIN)
	rm -rf ./evidence
