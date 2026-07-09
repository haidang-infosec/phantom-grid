# Single Packet Authorization (SPA)

Complete guide to understanding and using Single Packet Authorization in Phantom Grid.

## Table of Contents

- [What is SPA?](#what-is-spa)
- [How SPA Works](#how-spa-works)
- [SPA Modes](#spa-modes)
- [Key Management](#key-management)
- [Troubleshooting](#troubleshooting)

---

## What is SPA?

Single Packet Authorization (SPA) is a zero-trust access control mechanism that makes critical services **completely invisible** to network scans. Services are hidden until a client sends a valid "Magic Packet" to authenticate.

### Benefits

- **Invisibility**: Protected services don't respond to network scans
- **Zero Trust**: Every connection requires authentication
- **Replay Protection**: Time-based authentication prevents replay attacks
- **Cryptographic Security**: Uses modern cryptography (Ed25519, TOTP)

### How It Works

```
1. Server starts → All protected ports are DROPPED (invisible)
2. Client sends Magic Packet → UDP packet to port 1337
3. Server verifies packet → Checks signature, TOTP, timestamp
4. Server whitelists IP → IP can access protected ports for 30 seconds
5. Client connects → SSH, FTP, etc. now accessible
```

---

## How SPA Works

### Architecture

```
┌─────────────┐                    ┌─────────────┐
│   Client    │                    │   Server    │
│             │                    │             │
│ 1. Generate │                    │             │
│    Packet   │                    │             │
│             │                    │             │
│ 2. Send to  │ ────Magic Packet──▶│ 3. Verify  │
│    Port 1337│                    │    Packet   │
│             │                    │             │
│             │                    │ 4. Whitelist│
│             │                    │    IP      │
│             │                    │             │
│ 5. Connect  │ ────SSH/FTP───────▶│ 6. Allow   │
│    to Port  │                    │    Access  │
│    22/21    │                    │             │
└─────────────┘                    └─────────────┘
```

### Packet Flow

1. **Client generates SPA packet** with:
   - TOTP (Time-based One-Time Password)
   - Timestamp
   - Signature (Ed25519 or HMAC)

2. **Client sends packet** to server's port 1337 (UDP)

3. **Server receives packet** in user-space handler

4. **Server verifies**:
   - Signature is valid
   - TOTP is within tolerance window
   - Timestamp is recent (replay protection)

5. **Server whitelists IP** in eBPF map for 30 seconds

6. **Client can now access** protected ports

---

## SPA Modes

### Static Mode

**Security Level**: ⚠️ Low (Not recommended for production)

Simple token-based authentication. Token is sent in plaintext.

**Server:**
```bash
sudo ./bin/phantom-grid \
    -interface ens33 \
    -spa-mode static \
    -spa-static-token "my-secret-token"
```

**Client:**
```bash
./bin/spa-client \
    -server SERVER_IP \
    -mode static \
    -static-token "my-secret-token"
```

**Pros:**
- Simple to use
- No key management needed

**Cons:**
- Token sent in plaintext
- Vulnerable to replay attacks
- No cryptographic protection

### Dynamic Mode

**Security Level**: ✅ Good

HMAC-based authentication with TOTP for replay protection.

**Server:**
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

**Pros:**
- Replay protection (TOTP)
- HMAC authentication
- Time-based nonce

**Cons:**
- Requires shared secret (TOTP)
- Symmetric cryptography

### Asymmetric Mode (Recommended)

**Security Level**: ✅✅ Excellent

Ed25519 signatures with TOTP. Best security with public/private key cryptography.

**Server:**
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

**Pros:**
- Asymmetric cryptography (Ed25519)
- Replay protection (TOTP)
- Public key can be freely distributed
- Private key stays on client

**Cons:**
- Requires key management
- Slightly more complex setup

---

## Key Management

### Generating Keys

```bash
# Generate Ed25519 key pair
./bin/spa-keygen -dir ./keys

# Generate TOTP secret
openssl rand -base64 32 > keys/totp_secret.txt

# Set permissions
chmod 600 keys/spa_private.key
chmod 644 keys/spa_public.key
chmod 644 keys/totp_secret.txt
```

### Key Distribution

**Server Needs:**
- `spa_public.key` (for asymmetric mode)
- `totp_secret.txt` (for dynamic/asymmetric modes)

**Client Needs:**
- `spa_private.key` (for asymmetric mode)
- `totp_secret.txt` (for dynamic/asymmetric modes)

**Distribution Methods:**
1. **Out-of-band**: USB drive, secure email
2. **Encrypted channel**: SSH, TLS
3. **Key management system**: HashiCorp Vault, AWS Secrets Manager

### Key Rotation

1. Generate new keys
2. Distribute to all clients
3. Update server configuration
4. Restart agent
5. Revoke old keys

---

## Packet Structure

### Static Packet

```
[Token Bytes] (variable length)
```

### Dynamic Packet

```
[Version: 1][Mode: 1/2][TOTP: 4 bytes][Timestamp: 8 bytes][HMAC: 32 bytes][Padding: variable]
```

### Asymmetric Packet

```
[Version: 1][Mode: 2][TOTP: 4 bytes][Timestamp: 8 bytes][Signature: 64 bytes][Padding: variable]
```

---

## Security Features

### Replay Protection

- **TOTP**: Time-based one-time password changes every 30 seconds
- **Timestamp**: Packet timestamp must be recent
- **Replay Window**: Configurable window (default: 60 seconds)

### Cryptographic Protection

- **Ed25519**: Fast, secure digital signatures
- **HMAC-SHA256**: Message authentication for dynamic mode
- **TOTP**: RFC 4226 compliant time-based OTP

### Obfuscation

- **Random Padding**: Packets have random padding to avoid detection
- **Binary Format**: Not human-readable
- **Variable Length**: Makes pattern detection harder

---

## Troubleshooting

### Authentication Failed

**Check:**
1. Clock synchronization (NTP)
2. Key files match on client and server
3. TOTP secret matches
4. Network connectivity

**Solution:**
```bash
# Sync clock
sudo ntpdate -q pool.ntp.org

# Verify keys
diff keys/spa_public.key client-keys/spa_public.key

# Check TOTP secret
diff keys/totp_secret.txt client-keys/totp_secret.txt
```

### Replay Detected

**Cause**: Packet was sent multiple times too quickly

**Solution**: Wait for replay window to expire (default: 60 seconds)

### Invalid Signature

**Cause**: Wrong key pair or corrupted key file

**Solution:**
1. Regenerate keys
2. Verify key pair matches
3. Check file permissions

### Clock Skew

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

## Best Practices

### Production Deployment

1. **Use Asymmetric Mode**: Best security
2. **Rotate Keys Periodically**: Every 90 days
3. **Secure Key Storage**: Encrypt at rest
4. **Monitor Authentication**: Log all attempts
5. **Limit Access**: Only authorized clients

### Key Management

1. **Store Privately**: Private keys only on clients
2. **Distribute Securely**: Use encrypted channels
3. **Backup Keys**: Store backups securely
4. **Revoke Compromised Keys**: Immediately

### Network Security

1. **Firewall Rules**: Allow only port 1337/udp
2. **Rate Limiting**: Prevent brute force
3. **Monitoring**: Alert on failed attempts
4. **Logging**: Centralized logging (ELK)

---

## Advanced Topics

### Custom Whitelist Duration

Edit `internal/config/config.go`:
```go
const SPAWhitelistDuration = 60 // seconds
```

### Custom TOTP Time Step

Edit `internal/config/spa.go`:
```go
TOTPTimeStep: 60, // seconds (default: 30)
```

### Replay Window Configuration

Edit `internal/config/spa.go`:
```go
ReplayWindowSeconds: 120, // seconds (default: 60)
```

---

**Related Documentation**:
- [Quick Start Guide](quick-start.md)
- [Configuration Guide](configuration.md)
- [Troubleshooting](troubleshooting.md)

