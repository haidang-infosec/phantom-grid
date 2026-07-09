# Installation Guide

This guide covers installation of Phantom Grid on various platforms and environments.

## Table of Contents

- [System Requirements](#system-requirements)
- [Linux Installation](#linux-installation)
- [Docker Installation](#docker-installation)
- [Client-Only Installation](#client-only-installation)
- [Verification](#verification)
- [Post-Installation](#post-installation)

---

## System Requirements

### Server Requirements

- **Operating System**: Linux (Ubuntu 20.04+, Debian 11+, CentOS 8+, RHEL 8+)
- **Kernel Version**: 5.4+ (with eBPF/XDP support)
- **Go Version**: 1.21 or later
- **Build Tools**:
  - `clang` (10.0+)
  - `llvm` (10.0+)
  - `libbpf-dev` (or `libbpf-devel` on RHEL/CentOS)
  - `make`
  - `git`

### Client Requirements

- **Operating System**: Linux, Windows, or macOS
- **Go Version**: 1.21 or later (only needed for building)
- **No kernel dependencies required**

### Checking Requirements

```bash
# Check kernel version
uname -r

# Check Go version
go version

# Check for eBPF support
ls /sys/fs/bpf

# Check for required tools
clang --version
llvm-config --version
```

---

## Linux Installation

### Ubuntu/Debian

```bash
# Update package list
sudo apt update

# Install dependencies
sudo apt install -y \
    clang \
    llvm \
    libbpf-dev \
    golang-go \
    make \
    git \
    openssl

# Clone repository
git clone https://github.com/YOUR_USERNAME/phantom-grid.git
cd phantom-grid

# Install Go dependencies
go mod download

# Build the project
make build

# Verify installation
ls -lh bin/
```

### CentOS/RHEL

```bash
# Install EPEL repository (if not already installed)
sudo yum install -y epel-release

# Install dependencies
sudo yum install -y \
    clang \
    llvm \
    libbpf-devel \
    golang \
    make \
    git \
    openssl

# Clone repository
git clone https://github.com/YOUR_USERNAME/phantom-grid.git
cd phantom-grid

# Install Go dependencies
go mod download

# Build the project
make build

# Verify installation
ls -lh bin/
```

### Arch Linux

```bash
# Install dependencies
sudo pacman -S \
    clang \
    llvm \
    libbpf \
    go \
    make \
    git \
    openssl

# Clone and build
git clone https://github.com/YOUR_USERNAME/phantom-grid.git
cd phantom-grid
go mod download
make build
```

---

## Docker Installation

### Using Docker Compose

```bash
# Clone repository
git clone https://github.com/YOUR_USERNAME/phantom-grid.git
cd phantom-grid

# Build and start
docker-compose up -d

# View logs
docker-compose logs -f

# Stop
docker-compose down
```

### Using Dockerfile

```bash
# Build image
docker build -t phantom-grid:latest .

# Run container
docker run -d \
    --name phantom-grid \
    --cap-add=NET_ADMIN \
    --cap-add=SYS_ADMIN \
    --network host \
    phantom-grid:latest
```

**Note**: Docker deployment requires host network mode and additional capabilities for eBPF/XDP to work.

---

## Client-Only Installation

The SPA client can be built on any platform without eBPF dependencies.

### Build Client Only

```bash
# Clone repository
git clone https://github.com/YOUR_USERNAME/phantom-grid.git
cd phantom-grid

# Install Go dependencies
go mod download

# Build only client
make build-client

# Or manually
go build -o bin/spa-client ./cmd/spa-client
```

### Cross-Platform Build

```bash
# Build for Linux
GOOS=linux GOARCH=amd64 go build -o bin/spa-client-linux ./cmd/spa-client

# Build for Windows
GOOS=windows GOARCH=amd64 go build -o bin/spa-client.exe ./cmd/spa-client

# Build for macOS
GOOS=darwin GOARCH=amd64 go build -o bin/spa-client-macos ./cmd/spa-client
```

---

## Verification

### Verify Server Installation

```bash
# Check binaries
ls -lh bin/
# Should show:
# - phantom-grid (main agent)
# - spa-client (SPA client)
# - phantom (interactive menu)

# Test help command
sudo ./bin/phantom-grid -h

# Test interactive menu
./bin/phantom
```

### Verify Client Installation

```bash
# Check client binary
ls -lh bin/spa-client

# Test help command
./bin/spa-client -h
```

### Verify eBPF Support

```bash
# Check kernel version (must be 5.4+)
uname -r

# Check eBPF filesystem
ls /sys/fs/bpf

# Check XDP support
ip link show | grep -i xdp
```

---

## Post-Installation

### Generate SPA Keys

```bash
# Create keys directory
mkdir -p keys

# Generate Ed25519 key pair
./bin/spa-keygen -dir ./keys

# Generate TOTP secret
openssl rand -base64 32 > keys/totp_secret.txt

# Set proper permissions
chmod 600 keys/spa_private.key
chmod 644 keys/spa_public.key
chmod 644 keys/totp_secret.txt
```

### Create Systemd Service (Optional)

```bash
# Create service file
sudo tee /etc/systemd/system/phantom-grid.service > /dev/null <<EOF
[Unit]
Description=Phantom Grid Active Defense System
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/phantom-grid
ExecStart=/opt/phantom-grid/bin/phantom-grid \
    -interface ens33 \
    -spa-mode asymmetric \
    -spa-key-dir /opt/phantom-grid/keys
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

# Enable and start service
sudo systemctl daemon-reload
sudo systemctl enable phantom-grid
sudo systemctl start phantom-grid

# Check status
sudo systemctl status phantom-grid
```

### Firewall Configuration

```bash
# Allow SPA magic port (default: 1337)
sudo ufw allow 1337/udp

# Or for firewalld
sudo firewall-cmd --permanent --add-port=1337/udp
sudo firewall-cmd --reload
```

---

## Troubleshooting Installation

### Build Errors

**Error**: `clang: command not found`

```bash
# Install clang
sudo apt install clang  # Ubuntu/Debian
sudo yum install clang  # CentOS/RHEL
```

**Error**: `libbpf.h: No such file or directory`

```bash
# Install libbpf development package
sudo apt install libbpf-dev  # Ubuntu/Debian
sudo yum install libbpf-devel  # CentOS/RHEL
```

**Error**: `go: cannot find main module`

```bash
# Ensure you're in the project root
cd /path/to/phantom-grid
go mod download
```

### Runtime Errors

**Error**: `operation not permitted`

```bash
# Run with sudo
sudo ./bin/phantom-grid -interface ens33
```

**Error**: `failed to attach XDP: device or resource busy`

```bash
# Detach existing XDP program
sudo ip link set dev ens33 xdp off
```

---

## Next Steps

After installation:

1. **Generate Keys**: See [Quick Start Guide](quick-start.md)
2. **Configure**: See [Configuration Guide](configuration.md)
3. **Deploy**: See [Deployment Guide](deployment.md)

---

**Related Documentation**:

- [Quick Start Guide](quick-start.md)
- [Configuration Guide](configuration.md)
- [Troubleshooting](troubleshooting.md)
