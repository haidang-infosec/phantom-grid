CLANG ?= clang
CFLAGS := -O2 -g -Wall -Werror

# Go dependencies
GO_MOD := go.mod

all: generate-config generate build

generate-config:
	@echo "Generating eBPF configuration from Go config..."
	@go run ./cmd/config-gen

generate: generate-config
	go generate ./...

build: generate
	@mkdir -p bin
	cd cmd/agent && go build -o ../../bin/phantom-grid .
	cd cmd/fleet && go build -o ../../bin/fleet .
	cd cmd/spa-client && go build -o ../../bin/spa-client .
	cd cmd/phantom && go build -o ../../bin/phantom .
	@echo "Build complete: binaries in bin/"

# Build client only (for client machines - no eBPF dependencies needed)
build-client:
	@mkdir -p bin
	cd cmd/spa-client && go build -o ../../bin/spa-client .
	@echo "Client build complete: bin/spa-client"

run: build
	sudo ./bin/phantom-grid

# Run with specific interface
# Usage: make run-interface INTERFACE=ens33
run-interface: build
	sudo ./bin/phantom-grid -interface $(INTERFACE)

clean:
	rm -rf bin/
	rm -f phantom-grid spa-client phantom
	rm -f internal/ebpf/phantom_bpf*
	rm -f internal/ebpf/egress_bpf*
	rm -f internal/ebpf/programs/phantom_ports.h
	rm -f internal/ebpf/programs/phantom_ports_functions.c
	rm -f coverage.out coverage.html
	@echo "Clean complete"

deps:
	go mod tidy

fmt:
	gofmt -w ./cmd ./internal ./pkg

lint:
	go vet ./...

test: generate
	go test -v ./...

test-coverage: generate
	go test -v -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report generated: coverage.html"

.PHONY: all generate-config generate build build-client run run-interface clean deps fmt lint test test-coverage

