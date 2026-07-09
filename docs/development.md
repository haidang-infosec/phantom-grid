# Development Guide

Guide for contributing to Phantom Grid development.

## Table of Contents

- [Development Setup](#development-setup)
- [Project Structure](#project-structure)
- [Build System](#build-system)
- [Code Guidelines](#code-guidelines)
- [Testing](#testing)
- [Contributing](#contributing)

---

## Development Setup

### Prerequisites

- Go 1.21+
- Linux with kernel 5.4+
- clang, llvm, libbpf-dev
- make, git

### Setup Development Environment

```bash
# Clone repository
git clone https://github.com/YOUR_USERNAME/phantom-grid.git
cd phantom-grid

# Install dependencies
go mod download

# Generate eBPF bindings
make generate-config
make generate

# Build
make build

# Run tests
make test
```

### IDE Setup

**VS Code:**
- Install Go extension
- Install C/C++ extension (for eBPF code)

**GoLand:**
- Configure Go SDK
- Enable eBPF syntax highlighting

---

## Project Structure

```
phantom-grid/
├── cmd/                    # Application entry points
│   ├── agent/             # Main agent
│   ├── spa-client/        # SPA client CLI
│   ├── spa-keygen/        # Key generator
│   ├── config-gen/        # Config generator
│   └── phantom/           # Interactive menu
├── internal/              # Internal packages
│   ├── agent/             # Agent logic
│   ├── config/            # Configuration
│   ├── dashboard/         # Terminal UI
│   ├── ebpf/              # eBPF loader and programs
│   ├── honeypot/          # Honeypot implementation
│   ├── logger/            # Logging
│   ├── network/           # Network utilities
│   └── spa/               # SPA implementation
├── pkg/                   # Public packages
│   └── spa/               # SPA client library
├── docs/                  # Documentation
├── scripts/               # Utility scripts
└── examples/              # Example code
```

### Package Organization

- **cmd/**: One package per binary
- **internal/**: Private packages (not importable)
- **pkg/**: Public packages (importable)
- **docs/**: Documentation

---

## Build System

### Makefile Targets

```bash
make build          # Build all binaries
make build-client   # Build only client
make test           # Run tests
make test-coverage  # Run tests with coverage
make fmt            # Format code
make lint           # Lint code
make clean          # Clean build artifacts
make generate       # Generate eBPF bindings
make generate-config # Generate eBPF config
```

### eBPF Build Process

1. **Generate Config** (`make generate-config`)
   - Reads Go config files
   - Generates C headers (`phantom_ports.h`)
   - Generates C functions (`phantom_ports_functions.c`)

2. **Generate Bindings** (`make generate`)
   - Compiles eBPF C programs
   - Generates Go bindings
   - Creates `*_bpf.go` files

3. **Build Binaries** (`make build`)
   - Compiles Go code
   - Links eBPF programs
   - Creates binaries

---

## Code Guidelines

### Go Style

- Follow [Effective Go](https://go.dev/doc/effective_go)
- Use `gofmt` for formatting
- Follow standard Go project layout

### Naming Conventions

- **Packages**: lowercase, single word
- **Functions**: PascalCase for exported, camelCase for private
- **Variables**: camelCase
- **Constants**: PascalCase or UPPER_CASE

### Error Handling

```go
// Always handle errors explicitly
if err != nil {
    return fmt.Errorf("context: %w", err)
}

// Don't ignore errors
result, err := doSomething()
if err != nil {
    log.Printf("error: %v", err)
    return err
}
```

### Documentation

```go
// Package comment
package spa

// Function comment
// NewHandler creates a new SPA packet handler.
// It initializes the verifier and map loader.
func NewHandler(...) *Handler {
    // ...
}
```

### Concurrency

- Use channels for communication
- Use mutexes for shared state
- Avoid data races
- Document goroutine lifecycle

---

## Testing

### Unit Tests

```bash
# Run all tests
go test ./...

# Run specific package
go test ./internal/spa

# Run with verbose output
go test -v ./...

# Run with coverage
go test -cover ./...
```

### Test Coverage

```bash
# Generate coverage report
make test-coverage

# View HTML report
open coverage.html
```

### Writing Tests

```go
func TestFunction(t *testing.T) {
    // Arrange
    input := "test"
    
    // Act
    result, err := Function(input)
    
    // Assert
    if err != nil {
        t.Fatalf("unexpected error: %v", err)
    }
    if result != expected {
        t.Errorf("got %v, want %v", result, expected)
    }
}
```

### Integration Tests

- Test eBPF program loading
- Test SPA authentication flow
- Test honeypot connections

---

## Contributing

### Workflow

1. **Fork Repository**
   ```bash
   # Fork on GitHub, then clone
   git clone https://github.com/YOUR_USERNAME/phantom-grid.git
   ```

2. **Create Branch**
   ```bash
   git checkout -b feature/amazing-feature
   ```

3. **Make Changes**
   - Write code
   - Add tests
   - Update documentation

4. **Test Changes**
   ```bash
   make fmt
   make lint
   make test
   ```

5. **Commit Changes**
   ```bash
   git add .
   git commit -m "feat: add amazing feature"
   ```

6. **Push and Create PR**
   ```bash
   git push origin feature/amazing-feature
   # Create PR on GitHub
   ```

### Commit Messages

Follow [Conventional Commits](https://www.conventionalcommits.org/):

```
feat: add new feature
fix: fix bug
docs: update documentation
style: formatting changes
refactor: code refactoring
test: add tests
chore: maintenance tasks
```

### Pull Request Guidelines

- **Clear Title**: Describe what the PR does
- **Description**: Explain why and how
- **Tests**: Include tests for new features
- **Documentation**: Update docs if needed
- **Small PRs**: Keep PRs focused and small

---

## eBPF Development

### Writing eBPF Programs

1. **Write C Code** (`internal/ebpf/programs/`)
2. **Include Headers** (`phantom_ports.h`)
3. **Use BPF Helpers** (bpf_ktime_get_ns, etc.)
4. **Test Locally**
5. **Generate Bindings** (`make generate`)

### eBPF Best Practices

- **Keep it Simple**: eBPF has limitations
- **No Loops**: Use unroll pragma if needed
- **Bounded Memory**: Allocate statically
- **Verify**: Kernel verifier will check

### Debugging eBPF

```bash
# Check verifier logs
dmesg | tail -20

# Use bpftool
sudo bpftool prog show
sudo bpftool map show

# Trace execution
sudo bpftool prog tracelog
```

---

## Code Review Checklist

- [ ] Code follows style guidelines
- [ ] Tests are included
- [ ] Documentation is updated
- [ ] No security issues
- [ ] Error handling is proper
- [ ] No data races
- [ ] Performance is acceptable

---

## Release Process

1. **Update Version**
   - Update version in code
   - Update CHANGELOG

2. **Create Tag**
   ```bash
   git tag -a v1.0.0 -m "Release v1.0.0"
   git push origin v1.0.0
   ```

3. **Build Release**
   ```bash
   make build
   # Create release artifacts
   ```

4. **Publish**
   - Create GitHub release
   - Upload binaries
   - Announce release

---

**Related Documentation**:
- [Architecture Overview](architecture.md)
- [API Reference](api.md)
- [Troubleshooting](troubleshooting.md)

