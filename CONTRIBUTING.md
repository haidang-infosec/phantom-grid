## Contributing to Phantom Grid

Thank you for your interest in contributing to **Phantom Grid**!  
This project is designed as a serious security tool, so contributions must keep **security, reliability, and clarity** as top priorities.

---

## Code of Conduct

By participating in this project, you agree to follow the `CODE_OF_CONDUCT.md`.  
Be respectful, constructive, and professional.

---

## How to Ask Questions / Get Help

- **Bugs / Issues**: Open a GitHub Issue with:
  - **Environment** (OS, kernel version, Go version)
  - **What you did** (commands, configuration)
  - **What you expected** vs **what happened**
  - Any relevant logs from `logs/` or terminal output
- **Feature Requests**: Use the _Feature request_ issue template (see `.github/ISSUE_TEMPLATE`).

Please **do not** disclose security vulnerabilities in public issues. See `SECURITY.md` for details.

---

## Development Environment

- **Go**: Go 1.21+
- **OS**: Linux kernel 5.4+ recommended (Ubuntu 20.04/22.04)
- **Tools**:
  - `clang`, `llvm`, `libbpf-dev`
  - `make`, `git`

Basic setup:

```bash
git clone https://github.com/YOUR_USERNAME/phantom-grid.git
cd phantom-grid
go mod tidy
make build
```

Run the agent (requires root):

```bash
sudo make run
```

Or with a specific interface:

```bash
sudo ./phantom-grid -interface ens33
```

---

## Project Layout (High Level)

- `cmd/agent` – main Phantom Grid agent binary
- `cmd/spa-client` – SPA client CLI to send Magic Packet
- `internal/ebpf` – eBPF loader and generated bindings
- `internal/honeypot` – honeypot implementation and fake services
- `internal/dashboard` – terminal UI dashboard
- `internal/spa` – SPA manager and wrapper
- `internal/config` – ports, SPA config, and global settings
- `pkg/spa` – reusable SPA client package

The internal packages are **not** meant to be imported by external projects; only `pkg/` should be treated as public API.

---

## Coding Guidelines

- **Language**: Go
- **Style**:
  - Run `gofmt` on all Go files.
  - Keep functions small and focused when possible.
  - Prefer explicit, clear naming (security code must be easy to audit).
  - Handle errors explicitly; do not ignore them.
- **Concurrency / Safety**:
  - Be careful with goroutines and shared state.
  - Avoid data races; use channels or proper synchronization.
- **Security**:
  - Do not add debug backdoors or hardcoded credentials.
  - Be explicit about any trade-offs in comments and docs.

Before committing:

```bash
make fmt
make lint
make test
```

---

## Commit Messages

- Use clear, descriptive messages:
  - `fix: handle SPA timeout correctly`
  - `feat: add Redis egress DLP pattern`
  - `docs: clarify critical port behavior`
- Group related changes in a single commit where possible.

---

## Testing

Run unit tests:

```bash
make test
```

With coverage:

```bash
make test-coverage
```

If you add new logic in:

- `internal/agent`, `internal/honeypot`, `internal/dashboard`, or `pkg/spa`

…please add or update tests to cover the new behavior.

---

## Submitting a Pull Request

1. **Fork** the repository.
2. **Create a branch** for your change:
   ```bash
   git checkout -b feature/my-change
   ```
3. Make your changes and ensure:
   - `make fmt` passes
   - `make lint` passes
   - `make test` passes
4. Update documentation if behavior or usage changes:
   - `README.md`
   - `docs/PROJECT_STRUCTURE.md` (if project structure changes)
   - `AUDIT_REPORT.md` (if fixing logic issues)
5. Open a Pull Request:
   - Describe **what** you changed.
   - Explain **why** the change is needed.
   - Note any security impact or behavioral changes.

---

## Documentation Contributions

Improvements to documentation are very welcome:

- Better explanations of attack scenarios
- Clarifying how SPA, honeypot, and eBPF interact
- Translating or polishing Vietnamese/English sections

For significant design changes, consider adding or updating documentation:

- `README.md` - Main project documentation
- `docs/PROJECT_STRUCTURE.md` - Project layout explanation
- `AUDIT_REPORT.md` - Logic audit and known issues

---

## Security-Sensitive Changes

If your change affects:

- SPA logic
- eBPF packet handling
- Critical ports or honeypot redirection

…please:

- Document the threat model or behavior change.
- Add tests or step-by-step reproduction instructions.
- Clearly note any **backward-incompatible** behavior.

For reporting vulnerabilities, see `SECURITY.md`.
