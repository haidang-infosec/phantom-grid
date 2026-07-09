# Quick Start Guide

Get Phantom Grid up and running in 5 minutes.

## Prerequisites

- Linux server with kernel 5.4+
- Root/sudo access
- Network interface name (e.g., `ens33`, `eth0`)

---

## Step 1: Build the Project

```bash
# Clone repository
git clone https://github.com/YOUR_USERNAME/phantom-grid.git
cd phantom-grid

# Install dependencies (Ubuntu/Debian)
sudo apt update && sudo apt install -y clang llvm libbpf-dev golang-go make git

# Build
make build
```

---

## Step 2: Generate Keys

```bash
# Create keys directory
mkdir -p keys

# Generate Ed25519 key pair
./bin/spa-keygen -dir ./keys

# Generate TOTP secret
openssl rand -base64 32 > keys/totp_secret.txt

# Verify keys
ls -lh keys/
```

---

## Step 3: Start the Agent

### Option A: Interactive Menu (Recommended)

```bash
# Launch interactive menu
./bin/phantom
```

Then select:
1. **Agent Management** → **Start Agent (Interactive)**
2. Enter interface name (e.g., `ens33`)
3. Select SPA mode (e.g., `asymmetric`)
4. Agent will start automatically

### Option B: Command Line

```bash
# Start agent
sudo ./bin/phantom-grid \
    -interface ens33 \
    -spa-mode asymmetric \
    -spa-key-dir ./keys
```

---

## Step 4: Authenticate from Client

### On Client Machine

```bash
# Build client (if not already built)
make build-client

# Authenticate
./bin/spa-client \
    -server SERVER_IP \
    -mode asymmetric
```

**Note**: Keys must be copied to client machine:
- `keys/spa_private.key` (client needs private key)
- `keys/totp_secret.txt` (client needs TOTP secret)

---

## Step 5: Access Protected Services

After successful authentication, you have **30 seconds** to access protected services:

```bash
# SSH
ssh user@SERVER_IP

# FTP
ftp SERVER_IP
```

---

## Quick Test

### Test Static SPA Mode

**Server:**
```bash
sudo ./bin/phantom-grid \
    -interface ens33 \
    -spa-mode static \
    -spa-static-token "mytoken123"
```

**Client:**
```bash
./bin/spa-client \
    -server SERVER_IP \
    -mode static \
    -static-token "mytoken123"
```

---

## Common Commands

### View Help

```bash
# Agent help
sudo ./bin/phantom-grid -h

# Client help
./bin/spa-client -h

# Key generator help
./bin/spa-keygen -h
```

### Check Status

```bash
# Check if agent is running
ps aux | grep phantom-grid

# Check XDP attachment
ip link show | grep -i xdp

# Check listening ports
sudo netstat -tulpn | grep phantom
```

### Stop Agent

```bash
# If running in foreground: Ctrl+C

# If running as service
sudo systemctl stop phantom-grid

# If running in background
pkill phantom-grid
```

---

## Next Steps

- **Configure Ports**: See [Configuration Guide](configuration.md)
- **Understand SPA**: See [SPA Documentation](spa.md)
- **Production Deployment**: See [Deployment Guide](deployment.md)
- **Troubleshooting**: See [Troubleshooting Guide](troubleshooting.md)

---

## Quick Reference

| Task | Command |
|------|---------|
| Build | `make build` |
| Generate Keys | `./bin/spa-keygen -dir ./keys` |
| Start Agent | `sudo ./bin/phantom-grid -interface ens33 -spa-mode asymmetric -spa-key-dir ./keys` |
| Authenticate | `./bin/spa-client -server SERVER_IP -mode asymmetric` |
| Interactive Menu | `./bin/phantom` |

---

**Related Documentation**:
- [Installation Guide](installation.md)
- [Configuration Guide](configuration.md)
- [SPA Documentation](spa.md)

