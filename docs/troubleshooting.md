# Troubleshooting Guide

Common issues and solutions for Phantom Grid.

## Table of Contents

- [Installation Issues](#installation-issues)
- [Runtime Issues](#runtime-issues)
- [SPA Authentication Issues](#spa-authentication-issues)
- [Network Issues](#network-issues)
- [Performance Issues](#performance-issues)

---

## Installation Issues

### Build Errors

#### Error: `clang: command not found`

**Solution:**
```bash
# Ubuntu/Debian
sudo apt install clang

# CentOS/RHEL
sudo yum install clang
```

#### Error: `libbpf.h: No such file or directory`

**Solution:**
```bash
# Ubuntu/Debian
sudo apt install libbpf-dev

# CentOS/RHEL
sudo yum install libbpf-devel
```

#### Error: `go: cannot find main module`

**Solution:**
```bash
# Ensure you're in project root
cd /path/to/phantom-grid

# Download dependencies
go mod download
```

#### Error: `undefined: ebpf.PhantomObjects`

**Solution:**
This is expected on non-Linux systems. eBPF types are generated on Linux:

```bash
# On Linux system
make generate-config
make generate
make build
```

---

## Runtime Issues

### Permission Denied

#### Error: `operation not permitted`

**Solution:**
```bash
# Run with sudo
sudo ./bin/phantom-grid -interface ens33
```

#### Error: `failed to set memlock rlimit`

**Solution:**
```bash
# Increase memlock limit
ulimit -l unlimited

# Or edit /etc/security/limits.conf
* soft memlock unlimited
* hard memlock unlimited
```

### XDP Attachment Failed

#### Error: `device or resource busy`

**Solution:**
```bash
# Detach existing XDP program
sudo ip link set dev ens33 xdp off

# Wait a moment
sleep 2

# Retry
sudo ./bin/phantom-grid -interface ens33
```

#### Error: `XDP not supported on this device`

**Solution:**
- Check if interface supports XDP
- Try generic XDP mode (slower)
- Use different network interface

### Port Already in Use

#### Error: `bind: address already in use`

**Solution:**
```bash
# Find process using port
sudo lsof -i :1337
sudo lsof -i :9999

# Kill process
sudo kill -9 <PID>

# Or change port in configuration
```

---

## SPA Authentication Issues

### Authentication Failed

#### Error: `SPA authentication failed`

**Checklist:**
1. **Clock Synchronization**
   ```bash
   # Check time on both machines
   date
   
   # Sync time
   sudo ntpdate -q pool.ntp.org
   ```

2. **Key Mismatch**
   ```bash
   # Verify keys match
   diff keys/spa_public.key client-keys/spa_public.key
   
   # Regenerate if needed
   ./bin/spa-keygen -dir ./keys
   ```

3. **TOTP Secret Mismatch**
   ```bash
   # Verify TOTP secret
   diff keys/totp_secret.txt client-keys/totp_secret.txt
   
   # Regenerate if needed
   openssl rand -base64 32 > keys/totp_secret.txt
   ```

4. **Network Connectivity**
   ```bash
   # Test connectivity
   ping SERVER_IP
   
   # Test UDP port
   nc -u SERVER_IP 1337
   ```

### Replay Detected

#### Error: `replay detected`

**Cause**: Packet was sent multiple times too quickly

**Solution:**
- Wait for replay window to expire (default: 60 seconds)
- Increase replay window in configuration
- Check for packet duplication in network

### Invalid Signature

#### Error: `invalid signature`

**Cause**: Wrong key pair or corrupted key file

**Solution:**
```bash
# Regenerate keys
./bin/spa-keygen -dir ./keys

# Verify key pair
# Public key should match private key
```

### Clock Skew

#### Error: `TOTP validation failed`

**Cause**: Client and server clocks are out of sync

**Solution:**
```bash
# Sync both machines
sudo ntpdate -q pool.ntp.org

# Or use NTP daemon
sudo systemctl enable ntpd
sudo systemctl start ntpd
```

---

## Network Issues

### Interface Not Found

#### Error: `interface not found`

**Solution:**
```bash
# List available interfaces
ip link show

# Or
ifconfig

# Use correct interface name
sudo ./bin/phantom-grid -interface eth0
```

### No Traffic Captured

#### Issue: Agent running but no traffic

**Checklist:**
1. **Wrong Interface**
   ```bash
   # Check interface
   ip link show dev ens33
   
   # Verify IP address
   ip addr show dev ens33
   ```

2. **Loopback Interface**
   ```bash
   # Don't use loopback
   # Use external interface instead
   sudo ./bin/phantom-grid -interface ens33
   ```

3. **XDP Not Attached**
   ```bash
   # Check XDP attachment
   ip link show dev ens33 | grep xdp
   
   # Reattach if needed
   sudo systemctl restart phantom-grid
   ```

### Traffic Not Redirected

#### Issue: Traffic not going to honeypot

**Solution:**
```bash
# Check honeypot is running
ps aux | grep phantom-grid

# Check honeypot port
sudo netstat -tulpn | grep 9999

# Check XDP redirect
ip link show dev ens33 | grep xdp
```

---

## Performance Issues

### High CPU Usage

#### Issue: Agent using too much CPU

**Solutions:**
1. **Check for loops**
   ```bash
   # Profile CPU usage
   top -p $(pgrep phantom-grid)
   ```

2. **Reduce logging**
   - Disable debug logging
   - Use ELK instead of dashboard

3. **Optimize configuration**
   - Reduce number of fake ports
   - Disable unnecessary features

### High Memory Usage

#### Issue: Agent using too much memory

**Solutions:**
1. **Check BPF maps**
   ```bash
   # List BPF maps
   sudo bpftool map show
   ```

2. **Reduce whitelist size**
   - Limit number of whitelisted IPs
   - Reduce whitelist duration

3. **Check for leaks**
   ```bash
   # Monitor memory
   watch -n 1 'ps aux | grep phantom-grid'
   ```

### Packet Drops

#### Issue: Packets being dropped

**Check:**
```bash
# Check XDP statistics
ip -s link show dev ens33

# Check for drops
# Look for "dropped" counter
```

**Solutions:**
- Increase buffer sizes
- Check network interface driver
- Verify XDP mode (native vs generic)

---

## Debugging Tips

### Enable Debug Logging

```bash
# Run with verbose output
sudo ./bin/phantom-grid \
    -interface ens33 \
    -spa-mode asymmetric \
    2>&1 | tee debug.log
```

### Check BPF Maps

```bash
# List all maps
sudo bpftool map show

# Dump specific map
sudo bpftool map dump id <MAP_ID>

# Show map details
sudo bpftool map show id <MAP_ID>
```

### Test SPA Manually

```bash
# Generate packet
./bin/spa-client -server SERVER_IP -mode asymmetric -verbose

# Check server logs
sudo journalctl -u phantom-grid -f
```

### Network Debugging

```bash
# Capture packets
sudo tcpdump -i ens33 -n port 1337

# Check XDP attachment
ip link show dev ens33

# Check routing
ip route show
```

---

## Getting Help

### Before Asking for Help

1. **Check Logs**
   ```bash
   sudo journalctl -u phantom-grid -n 100
   ```

2. **Gather Information**
   - Kernel version: `uname -r`
   - Go version: `go version`
   - Interface: `ip link show`
   - Error messages: Full output

3. **Reproduce Issue**
   - Steps to reproduce
   - Expected vs actual behavior
   - Configuration used

### Resources

- **GitHub Issues**: Report bugs and feature requests
- **Documentation**: Check all docs first
- **Community**: Ask in discussions

---

## Common Solutions Summary

| Issue | Quick Fix |
|-------|-----------|
| Permission denied | Use `sudo` |
| XDP busy | `sudo ip link set dev INTERFACE xdp off` |
| Port in use | Kill process or change port |
| SPA failed | Check clock sync and keys |
| No traffic | Check interface and XDP attachment |
| High CPU | Disable debug logging |

---

**Related Documentation**:
- [Installation Guide](installation.md)
- [Configuration Guide](configuration.md)
- [SPA Documentation](spa.md)

