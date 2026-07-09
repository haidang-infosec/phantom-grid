# Configuration Guide

Complete guide to configuring Phantom Grid for your environment.

## Table of Contents

- [Configuration Overview](#configuration-overview)
- [Port Configuration](#port-configuration)
- [SPA Configuration](#spa-configuration)
- [Output Configuration](#output-configuration)
- [Network Configuration](#network-configuration)
- [Advanced Configuration](#advanced-configuration)

---

## Configuration Overview

Phantom Grid uses a centralized configuration system where all settings are defined in Go code and automatically generated into eBPF C headers. This ensures consistency and eliminates manual synchronization errors.

### Configuration Files

- `internal/config/config.go` - Core constants (ports, tokens, durations)
- `internal/config/ports.go` - Port definitions (critical and fake ports)
- `internal/config/constants.go` - eBPF constants (OS fingerprint, DLP settings)
- `internal/config/spa.go` - SPA configuration (modes, keys, TOTP)

### Regenerating Configuration

After modifying configuration:

```bash
# Regenerate eBPF headers from Go config
make generate-config

# Rebuild
make build
```

---

## Port Configuration

### Protected Ports (Critical Ports)

Protected ports require SPA authentication before access. Default: **Ports 21 (FTP) and 22 (SSH)**

**Location**: `internal/config/ports.go`

```go
var CriticalPortDefinitions = []PortDefinition{
    {Port: 21, Name: "FTP", Protocol: "TCP", Description: "File Transfer Protocol"},
    {Port: 22, Name: "SSH", Protocol: "TCP", Description: "Secure Shell"},
    // Add more ports here
}
```

### Adding a Protected Port

1. Edit `internal/config/ports.go`:

```go
var CriticalPortDefinitions = []PortDefinition{
    {Port: 21, Name: "FTP", Protocol: "TCP"},
    {Port: 22, Name: "SSH", Protocol: "TCP"},
    {Port: 3306, Name: "MySQL", Protocol: "TCP"},  // Add this
}
```

2. Regenerate and rebuild:

```bash
make generate-config
make build
```

3. Restart agent:

```bash
sudo ./bin/phantom-grid -interface ens33
```

### Fake Ports (Honeypot Ports)

Fake ports are used for deception - they appear open but redirect to honeypots.

**Location**: `internal/config/ports.go`

```go
var FakePortDefinitions = []PortDefinition{
    {Port: 3389, Name: "RDP", Protocol: "TCP"},
    {Port: 3306, Name: "MySQL", Protocol: "TCP"},
    // ... more fake ports
}
```

---

## SPA Configuration

### SPA Modes

Phantom Grid supports three SPA modes:

#### 1. Static Mode

Simple token-based authentication. **Not recommended for production.**

```bash
sudo ./bin/phantom-grid \
    -interface ens33 \
    -spa-mode static \
    -spa-static-token "your-secret-token"
```

**Client:**
```bash
./bin/spa-client \
    -server SERVER_IP \
    -mode static \
    -static-token "your-secret-token"
```

#### 2. Dynamic Mode

HMAC-based authentication with TOTP. **Good for production.**

```bash
sudo ./bin/phantom-grid \
    -interface ens33 \
    -spa-mode dynamic \
    -spa-key-dir ./keys \
    -spa-totp-secret "$(cat keys/totp_secret.txt)"
```

**Client:**
```bash
./bin/spa-client \
    -server SERVER_IP \
    -mode dynamic
```

#### 3. Asymmetric Mode (Recommended)

Ed25519 signatures with TOTP. **Best for production.**

```bash
sudo ./bin/phantom-grid \
    -interface ens33 \
    -spa-mode asymmetric \
    -spa-key-dir ./keys \
    -spa-totp-secret "$(cat keys/totp_secret.txt)"
```

**Client:**
```bash
./bin/spa-client \
    -server SERVER_IP \
    -mode asymmetric
```

### SPA Whitelist Duration

Default: **30 seconds**

**Location**: `internal/config/config.go`

```go
const SPAWhitelistDuration = 30 // seconds
```

To change:

1. Edit `internal/config/config.go`
2. Regenerate: `make generate-config`
3. Rebuild: `make build`

### SPA Magic Port

Default: **1337**

**Location**: `internal/config/config.go`

```go
const SPAMagicPort = 1337
```

---

## Output Configuration

### Output Modes

#### Dashboard Only (Default)

```bash
sudo ./bin/phantom-grid \
    -interface ens33 \
    -output dashboard
```

#### ELK Only

```bash
sudo ./bin/phantom-grid \
    -interface ens33 \
    -output elk \
    -elk-address http://localhost:9200 \
    -elk-index phantom-grid
```

#### Both Dashboard and ELK

```bash
sudo ./bin/phantom-grid \
    -interface ens33 \
    -output both \
    -elk-address http://localhost:9200 \
    -elk-index phantom-grid \
    -elk-user elastic \
    -elk-pass changeme
```

### ELK Configuration

**Options:**
- `-elk-address`: Elasticsearch address (default: `http://localhost:9200`)
- `-elk-index`: Index name (default: `phantom-grid`)
- `-elk-user`: Username (optional)
- `-elk-pass`: Password (optional)
- `-elk-tls`: Enable TLS
- `-elk-skip-verify`: Skip TLS verification (testing only)

---

## Network Configuration

### Interface Selection

**Auto-detect (Testing Only):**
```bash
sudo ./bin/phantom-grid
```

**Specify Interface (Recommended):**
```bash
sudo ./bin/phantom-grid -interface ens33
```

**List Available Interfaces:**
```bash
ip link show
# or
ifconfig
```

### Interface Requirements

- Must be a physical or bridge interface
- Must have an IP address assigned
- Must support XDP (most modern NICs)
- Loopback (`lo`) is not recommended for production

---

## Advanced Configuration

### OS Fingerprint Mutation

Configure TTL and window size values for OS fingerprint spoofing.

**Location**: `internal/config/constants.go`

```go
OSFingerprint: OSFingerprintConfig{
    WindowsTTL: 128,
    LinuxTTL: 64,
    FreeBSDTTL: 64,
    SolarisTTL: 255,
    WindowsWindowSize: 65535,
    LinuxWindowSize: 29200,
    FreeBSDWindowSize: 65535,
}
```

### DLP (Data Loss Prevention)

Configure egress monitoring settings.

**Location**: `internal/config/constants.go`

```go
DLP: DLPConfig{
    MaxPayloadScan: 512, // bytes
}
```

### Honeypot Configuration

**Honeypot Port**: Default `9999`

**Location**: `internal/config/config.go`

```go
const HoneypotPort = 9999
```

---

## Configuration Best Practices

### Production Recommendations

1. **Use Asymmetric SPA Mode**: Most secure option
2. **Change Default Token**: Never use default static token
3. **Specify Interface**: Always use `-interface` flag
4. **Secure Key Storage**: Encrypt keys at rest
5. **Enable ELK Logging**: For centralized monitoring
6. **Rotate Keys Periodically**: Security best practice

### Security Considerations

- **Key Management**: Store private keys securely (encrypted)
- **TOTP Secret**: Distribute securely (out-of-band)
- **Network Interface**: Use external interface, not loopback
- **Firewall**: XDP operates before iptables/firewalld
- **Access Control**: Limit who can send SPA packets

---

## Configuration Examples

### Minimal Configuration

```bash
sudo ./bin/phantom-grid -interface ens33
```

### Production Configuration

```bash
sudo ./bin/phantom-grid \
    -interface ens33 \
    -spa-mode asymmetric \
    -spa-key-dir /etc/phantom-grid/keys \
    -output both \
    -elk-address https://elasticsearch.example.com:9200 \
    -elk-index phantom-grid-prod \
    -elk-user phantom \
    -elk-pass "$(cat /etc/phantom-grid/elk-password)" \
    -elk-tls
```

### Development Configuration

```bash
sudo ./bin/phantom-grid \
    -interface ens33 \
    -spa-mode static \
    -spa-static-token "dev-token" \
    -output dashboard
```

---

## Verifying Configuration

### Check Current Configuration

```bash
# View agent help (shows all options)
sudo ./bin/phantom-grid -h

# Check running configuration
ps aux | grep phantom-grid

# Check XDP attachment
ip link show dev ens33 | grep xdp
```

### Test Configuration

```bash
# Test SPA authentication
./bin/spa-client -server SERVER_IP -mode asymmetric

# Check logs
sudo journalctl -u phantom-grid -f
```

---

## Troubleshooting Configuration

### Configuration Not Applied

1. Ensure you regenerated config: `make generate-config`
2. Ensure you rebuilt: `make build`
3. Restart agent after changes

### Port Not Protected

1. Verify port is in `CriticalPortDefinitions`
2. Regenerate config: `make generate-config`
3. Rebuild: `make build`
4. Restart agent

### SPA Not Working

1. Check keys are in correct location
2. Verify TOTP secret matches on client and server
3. Check clock synchronization (NTP)
4. See [Troubleshooting Guide](troubleshooting.md)

---

**Related Documentation**:
- [Quick Start Guide](quick-start.md)
- [SPA Documentation](spa.md)
- [Troubleshooting](troubleshooting.md)

