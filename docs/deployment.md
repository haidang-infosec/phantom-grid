# Deployment Guide

Production deployment best practices for Phantom Grid.

## Table of Contents

- [Pre-Deployment Checklist](#pre-deployment-checklist)
- [Systemd Service](#systemd-service)
- [Docker Deployment](#docker-deployment)
- [Kubernetes Deployment](#kubernetes-deployment)
- [Monitoring](#monitoring)
- [Backup and Recovery](#backup-and-recovery)

---

## Pre-Deployment Checklist

### System Requirements

- [ ] Linux kernel 5.4+ with eBPF support
- [ ] Network interface with XDP support
- [ ] Root/sudo access for agent
- [ ] Firewall configured
- [ ] NTP synchronized
- [ ] Sufficient disk space for logs

### Security Checklist

- [ ] SPA keys generated and secured
- [ ] Default tokens changed
- [ ] Keys encrypted at rest
- [ ] Access control configured
- [ ] Logging enabled
- [ ] Monitoring configured

### Network Checklist

- [ ] Interface identified and tested
- [ ] Port 1337/udp allowed in firewall
- [ ] Protected ports identified
- [ ] Network connectivity verified
- [ ] DNS resolution working

---

## Systemd Service

### Create Service File

```bash
sudo tee /etc/systemd/system/phantom-grid.service > /dev/null <<EOF
[Unit]
Description=Phantom Grid Active Defense System
Documentation=https://github.com/YOUR_USERNAME/phantom-grid
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/phantom-grid
ExecStart=/opt/phantom-grid/bin/phantom-grid \
    -interface ens33 \
    -spa-mode asymmetric \
    -spa-key-dir /opt/phantom-grid/keys \
    -output both \
    -elk-address https://elasticsearch.example.com:9200 \
    -elk-index phantom-grid \
    -elk-user phantom \
    -elk-pass-file /opt/phantom-grid/.elk-password
Restart=on-failure
RestartSec=5
StandardOutput=journal
StandardError=journal

# Security settings
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/opt/phantom-grid

[Install]
WantedBy=multi-user.target
EOF
```

### Enable and Start

```bash
# Reload systemd
sudo systemctl daemon-reload

# Enable service
sudo systemctl enable phantom-grid

# Start service
sudo systemctl start phantom-grid

# Check status
sudo systemctl status phantom-grid

# View logs
sudo journalctl -u phantom-grid -f
```

### Service Management

```bash
# Start
sudo systemctl start phantom-grid

# Stop
sudo systemctl stop phantom-grid

# Restart
sudo systemctl restart phantom-grid

# Reload configuration
sudo systemctl reload phantom-grid

# Check status
sudo systemctl status phantom-grid
```

---

## Docker Deployment

### Dockerfile

```dockerfile
FROM golang:1.21-alpine AS builder

# Install build dependencies
RUN apk add --no-cache \
    clang \
    llvm \
    libbpf-dev \
    make \
    git

WORKDIR /build

# Copy source
COPY . .

# Build
RUN make build

# Runtime image
FROM alpine:latest

RUN apk add --no-cache \
    libbpf \
    ca-certificates

WORKDIR /opt/phantom-grid

# Copy binaries
COPY --from=builder /build/bin ./bin
COPY --from=builder /build/keys ./keys

# Run
CMD ["./bin/phantom-grid", "-interface", "eth0"]
```

### Docker Compose

```yaml
version: '3.8'

services:
  phantom-grid:
    build: .
    container_name: phantom-grid
    network_mode: host
    privileged: true
    volumes:
      - ./keys:/opt/phantom-grid/keys:ro
      - ./logs:/opt/phantom-grid/logs
    environment:
      - INTERFACE=ens33
      - SPA_MODE=asymmetric
    restart: unless-stopped
    cap_add:
      - NET_ADMIN
      - SYS_ADMIN
```

### Run

```bash
# Build and start
docker-compose up -d

# View logs
docker-compose logs -f

# Stop
docker-compose down
```

---

## Kubernetes Deployment

### ConfigMap

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: phantom-grid-config
data:
  interface: "eth0"
  spa-mode: "asymmetric"
  output: "both"
```

### Secret

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: phantom-grid-keys
type: Opaque
data:
  spa_public.key: <base64-encoded>
  totp_secret.txt: <base64-encoded>
```

### Deployment

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: phantom-grid
spec:
  replicas: 1
  selector:
    matchLabels:
      app: phantom-grid
  template:
    metadata:
      labels:
        app: phantom-grid
    spec:
      hostNetwork: true
      containers:
      - name: phantom-grid
        image: phantom-grid:latest
        securityContext:
          privileged: true
          capabilities:
            add:
              - NET_ADMIN
              - SYS_ADMIN
        volumeMounts:
        - name: keys
          mountPath: /opt/phantom-grid/keys
          readOnly: true
      volumes:
      - name: keys
        secret:
          secretName: phantom-grid-keys
```

---

## Monitoring

### Health Checks

```bash
# Check service status
sudo systemctl status phantom-grid

# Check XDP attachment
ip link show dev ens33 | grep xdp

# Check listening ports
sudo netstat -tulpn | grep phantom

# Check BPF maps
sudo bpftool map show
```

### Metrics

**Key Metrics to Monitor**:
- SPA authentication success/failure rate
- Whitelisted IP count
- Honeypot connections
- Egress blocks (DLP)
- System resource usage

### Logging

**Log Locations**:
- Systemd: `journalctl -u phantom-grid`
- ELK: Configured Elasticsearch index
- Dashboard: Terminal output

**Log Rotation**:

```bash
# Create logrotate config
sudo tee /etc/logrotate.d/phantom-grid > /dev/null <<EOF
/opt/phantom-grid/logs/*.log {
    daily
    rotate 7
    compress
    delaycompress
    missingok
    notifempty
}
EOF
```

---

## Backup and Recovery

### Backup

**What to Backup**:
- SPA keys (`keys/` directory)
- Configuration files
- Logs (if needed)

```bash
# Backup keys
tar -czf phantom-grid-keys-$(date +%Y%m%d).tar.gz keys/

# Backup configuration
tar -czf phantom-grid-config-$(date +%Y%m%d).tar.gz \
    internal/config/

# Store backups securely
# - Encrypted storage
# - Off-site backup
# - Access control
```

### Recovery

**Key Recovery**:
```bash
# Extract keys
tar -xzf phantom-grid-keys-YYYYMMDD.tar.gz

# Verify keys
ls -lh keys/

# Restart service
sudo systemctl restart phantom-grid
```

**Configuration Recovery**:
```bash
# Extract configuration
tar -xzf phantom-grid-config-YYYYMMDD.tar.gz

# Regenerate eBPF headers
make generate-config

# Rebuild
make build

# Restart service
sudo systemctl restart phantom-grid
```

---

## Production Best Practices

### Security

1. **Key Management**
   - Encrypt keys at rest
   - Use key management system (Vault, AWS KMS)
   - Rotate keys periodically
   - Limit key access

2. **Network Security**
   - Use firewall rules
   - Limit SPA packet source IPs
   - Monitor authentication attempts
   - Enable rate limiting

3. **Access Control**
   - Use asymmetric SPA mode
   - Implement key rotation
   - Monitor for unauthorized access
   - Log all authentication events

### Performance

1. **Resource Limits**
   - Set CPU limits
   - Set memory limits
   - Monitor resource usage

2. **Network Optimization**
   - Use dedicated network interface
   - Tune XDP buffer sizes
   - Monitor packet drops

3. **Scaling**
   - Horizontal scaling (multiple instances)
   - Load balancing
   - High availability setup

### Reliability

1. **High Availability**
   - Multiple instances
   - Health checks
   - Automatic failover

2. **Disaster Recovery**
   - Regular backups
   - Recovery procedures
   - Testing recovery

3. **Monitoring**
   - Health checks
   - Alerting
   - Logging

---

## Troubleshooting Deployment

### Service Won't Start

```bash
# Check logs
sudo journalctl -u phantom-grid -n 50

# Check permissions
ls -la /opt/phantom-grid/bin/phantom-grid

# Check interface
ip link show dev ens33
```

### XDP Attachment Failed

```bash
# Detach existing XDP
sudo ip link set dev ens33 xdp off

# Check interface support
ethtool -i ens33 | grep driver

# Retry
sudo systemctl restart phantom-grid
```

### Keys Not Found

```bash
# Check key location
ls -la /opt/phantom-grid/keys/

# Verify permissions
chmod 600 keys/spa_private.key
chmod 644 keys/spa_public.key

# Check service configuration
sudo systemctl cat phantom-grid
```

---

**Related Documentation**:
- [Installation Guide](installation.md)
- [Configuration Guide](configuration.md)
- [Troubleshooting](troubleshooting.md)

