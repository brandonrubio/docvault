.PHONY: up down test test-docker model-test run
up:        ; docker compose up -d openfga
down:      ; docker compose down
run:       ; OPENFGA_API_URL=http://localhost:8080 go run ./cmd/server
test:      ; OPENFGA_API_URL=http://localhost:8080 go test -race ./...
model-test: ; docker run --rm -v "$(CURDIR):/src" -w /src openfga/cli:latest model test --tests internal/authz/model.fga.yaml

# Run the full test suite without Go installed locally (needs `make up` first).
test-docker:
	docker run --rm --network host --user $$(id -u):$$(id -g) -e HOME=/tmp -e GOCACHE=/tmp/gocache -e GOPATH=/tmp/gopath \
		-e OPENFGA_API_URL=http://localhost:8080 -v "$(CURDIR):/src" -w /src golang:1.26 go test -race -count=1 ./...
