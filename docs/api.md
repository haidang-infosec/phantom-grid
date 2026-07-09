# API Reference

Complete reference for Phantom Grid command-line interface and configuration.

## Table of Contents

- [Agent CLI](#agent-cli)
- [SPA Client CLI](#spa-client-cli)
- [Key Generator CLI](#key-generator-cli)
- [Interactive Menu](#interactive-menu)
- [Configuration API](#configuration-api)

---

## Agent CLI

### Command

```bash
sudo ./bin/phantom-grid [OPTIONS]
```

### Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `-interface` | string | auto | Network interface name |
| `-output` | string | dashboard | Output mode: dashboard, elk, both |
| `-spa-mode` | string | static | SPA mode: static, dynamic, asymmetric |
| `-spa-key-dir` | string | ./keys | Directory containing SPA keys |
| `-spa-static-token` | string | - | Static SPA token (for static mode) |
| `-spa-totp-secret` | string | - | TOTP secret (for dynamic/asymmetric) |
| `-elk-address` | string | http://localhost:9200 | Elasticsearch address |
| `-elk-index` | string | phantom-grid | Elasticsearch index name |
| `-elk-user` | string | - | Elasticsearch username |
| `-elk-pass` | string | - | Elasticsearch password |
| `-elk-tls` | flag | false | Enable TLS for Elasticsearch |
| `-elk-skip-verify` | flag | false | Skip TLS verification |
| `-h, -help` | flag | - | Show help message |

### Examples

**Basic Usage:**
```bash
sudo ./bin/phantom-grid -interface ens33
```

**Static SPA Mode:**
```bash
sudo ./bin/phantom-grid \
    -interface ens33 \
    -spa-mode static \
    -spa-static-token "mytoken"
```

**Asymmetric SPA Mode:**
```bash
sudo ./bin/phantom-grid \
    -interface ens33 \
    -spa-mode asymmetric \
    -spa-key-dir ./keys \
    -spa-totp-secret "$(cat keys/totp_secret.txt)"
```

**ELK Output:**
```bash
sudo ./bin/phantom-grid \
    -interface ens33 \
    -output elk \
    -elk-address https://elasticsearch.example.com:9200 \
    -elk-index phantom-grid \
    -elk-user elastic \
    -elk-pass changeme \
    -elk-tls
```

---

## SPA Client CLI

### Command

```bash
./bin/spa-client [OPTIONS]
```

### Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `-server` | string | required | Server IP address |
| `-mode` | string | static | SPA mode: static, dynamic, asymmetric |
| `-static-token` | string | - | Static token (for static mode) |
| `-private-key` | string | auto | Path to private key |
| `-totp-secret` | string | auto | Path to TOTP secret |
| `-h, -help` | flag | - | Show help message |

### Examples

**Static Mode:**
```bash
./bin/spa-client \
    -server 192.168.1.100 \
    -mode static \
    -static-token "mytoken"
```

**Asymmetric Mode:**
```bash
./bin/spa-client \
    -server 192.168.1.100 \
    -mode asymmetric
```

**Custom Key Paths:**
```bash
./bin/spa-client \
    -server 192.168.1.100 \
    -mode asymmetric \
    -private-key /path/to/private.key \
    -totp-secret /path/to/totp_secret.txt
```

---

## Key Generator CLI

### Command

```bash
./bin/spa-keygen [OPTIONS]
```

### Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `-dir` | string | ./keys | Output directory |
| `-h, -help` | flag | - | Show help message |

### Examples

**Generate Keys:**
```bash
./bin/spa-keygen -dir ./keys
```

**Output:**
- `spa_public.key` - Public key (Ed25519)
- `spa_private.key` - Private key (Ed25519)

---

## Interactive Menu

### Command

```bash
./bin/phantom
```

### Menu Options

1. **Key Management**
   - Generate keys
   - View key status
   - Check key files

2. **Agent Management**
   - Start agent (interactive)
   - Start agent (background)
   - Stop agent
   - View agent status
   - Configure agent

3. **SPA Testing**
   - Quick send SPA
   - Custom SPA
   - Static SPA

4. **Configuration**
   - View configuration
   - Edit configuration
   - Validate configuration

5. **System Information**
   - Interface information
   - System status
   - Version information

6. **Documentation**
   - View documentation
   - Open documentation files

---

## Configuration API

### Port Configuration

**File**: `internal/config/ports.go`

```go
type PortDefinition struct {
    Port        uint16
    Name        string
    Protocol    string
    Description string
}

var CriticalPortDefinitions = []PortDefinition{
    {Port: 21, Name: "FTP", Protocol: "TCP"},
    {Port: 22, Name: "SSH", Protocol: "TCP"},
}

var FakePortDefinitions = []PortDefinition{
    {Port: 3389, Name: "RDP", Protocol: "TCP"},
    // ...
}
```

### Core Configuration

**File**: `internal/config/config.go`

```go
const (
    SPAMagicPort        = 1337
    SPASecretToken      = "PHANTOM_GRID_SECRET"
    SPATokenLen         = 20
    SPAWhitelistDuration = 30 // seconds
    HoneypotPort        = 9999
    SSHPort             = 22
)
```

### SPA Configuration

**File**: `internal/config/spa.go`

```go
type SPAMode int

const (
    SPAModeStatic SPAMode = iota
    SPAModeDynamic
    SPAModeAsymmetric
)

type DynamicSPAConfig struct {
    Mode                SPAMode
    PublicKey           ed25519.PublicKey
    PrivateKey          ed25519.PrivateKey
    TOTPSecret          []byte
    TOTPTimeStep        int
    TOTPTolerance       int
    ReplayWindowSeconds int
    HMACSecret          []byte
}
```

### eBPF Constants

**File**: `internal/config/constants.go`

```go
type EBPFConstants struct {
    OSFingerprint OSFingerprintConfig
    DLP           DLPConfig
}

type OSFingerprintConfig struct {
    WindowsTTL        uint8
    LinuxTTL          uint8
    FreeBSDTTL        uint8
    SolarisTTL        uint8
    WindowsWindowSize uint16
    LinuxWindowSize    uint16
    FreeBSDWindowSize uint16
}

type DLPConfig struct {
    MaxPayloadScan int
}
```

---

## Programmatic API

### SPA Client Library

**Package**: `pkg/spa`

```go
import "phantom-grid/pkg/spa"

// Create client
client := spa.NewClientWithToken("mytoken")

// Send magic packet
err := client.SendMagicPacket("192.168.1.100")
```

### Configuration Generator

**Package**: `cmd/config-gen`

```go
// Generate eBPF headers from Go config
// Run: go run ./cmd/config-gen
```

---

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `PHANTOM_INTERFACE` | Network interface | auto |
| `PHANTOM_SPA_MODE` | SPA mode | static |
| `PHANTOM_KEY_DIR` | Key directory | ./keys |
| `PHANTOM_ELK_ADDRESS` | Elasticsearch address | http://localhost:9200 |

---

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success |
| 1 | General error |
| 2 | Configuration error |
| 3 | Permission error |
| 4 | Network error |

---

## Logging

### Log Levels

- `[SYSTEM]` - System messages
- `[SPA]` - SPA authentication events
- `[HONEYPOT]` - Honeypot events
- `[ERROR]` - Error messages
- `[DEBUG]` - Debug messages (verbose)

### Log Format

```
[TIMESTAMP] [LEVEL] Message
```

Example:
```
2025-01-01 12:00:00 [SPA] Successfully authenticated and whitelisted IP: 192.168.1.100
```

---

**Related Documentation**:
- [Quick Start Guide](quick-start.md)
- [Configuration Guide](configuration.md)
- [Development Guide](development.md)

