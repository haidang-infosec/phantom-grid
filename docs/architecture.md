# Architecture Overview

Understanding the architecture and design principles of Phantom Grid.

## Table of Contents

- [System Architecture](#system-architecture)
- [Component Overview](#component-overview)
- [Data Flow](#data-flow)
- [eBPF Programs](#ebpf-programs)
- [User-Space Components](#user-space-components)
- [Design Principles](#design-principles)

---

## System Architecture

### High-Level Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Phantom Grid System                       │
└─────────────────────────────────────────────────────────────┘

┌──────────────┐         ┌──────────────┐         ┌──────────────┐
│   Client     │         │   Network    │         │   Server     │
│              │         │  Interface   │         │              │
│  SPA Client  │────────▶│   (ens33)    │────────▶│  Phantom     │
│              │         │              │         │  Grid Agent  │
└──────────────┘         └──────┬───────┘         └──────┬───────┘
                                │                        │
                                ▼                        ▼
                         ┌──────────────┐         ┌──────────────┐
                         │  eBPF/XDP    │         │  User-Space  │
                         │   Program    │         │   Handler    │
                         │              │         │              │
                         │ • Packet     │         │ • SPA Verify │
                         │   Filtering  │         │ • Whitelist  │
                         │ • Redirect   │         │ • Honeypot   │
                         │ • OS Mutation│         │ • Dashboard  │
                         └──────────────┘         └──────────────┘
```

### Layer Architecture

```
┌─────────────────────────────────────────┐
│         Application Layer               │
│  (Dashboard, ELK Exporter, CLI)        │
└─────────────────────────────────────────┘
                    │
┌─────────────────────────────────────────┐
│         User-Space Layer                │
│  (Agent, SPA Handler, Honeypot)         │
└─────────────────────────────────────────┘
                    │
┌─────────────────────────────────────────┐
│         Kernel Layer (eBPF/XDP)         │
│  (Packet Processing, Filtering)         │
└─────────────────────────────────────────┘
                    │
┌─────────────────────────────────────────┐
│         Network Interface               │
│  (NIC Driver, Network Stack)            │
└─────────────────────────────────────────┘
```

---

## Component Overview

### 1. eBPF/XDP Programs

**Location**: `internal/ebpf/programs/`

#### phantom.c (Main XDP Program)

- **Purpose**: Ingress packet processing
- **Functions**:
  - Port filtering (critical vs fake ports)
  - SPA packet detection
  - Traffic redirection to honeypot
  - OS fingerprint mutation
  - Whitelist checking

#### phantom_egress.c (TC Egress Program)

- **Purpose**: Egress packet monitoring
- **Functions**:
  - Data Loss Prevention (DLP)
  - Sensitive data detection
  - Egress traffic blocking

#### phantom_spa.c (SPA Handler)

- **Purpose**: SPA packet processing
- **Functions**:
  - Static token verification
  - Whitelist management
  - Authentication statistics

### 2. User-Space Agent

**Location**: `internal/agent/`

**Responsibilities**:
- Load and attach eBPF programs
- Manage SPA handler
- Start honeypot server
- Coordinate all components
- Handle logging and output

### 3. SPA Handler

**Location**: `internal/spa/`

**Components**:
- **Handler**: UDP listener for SPA packets
- **Verifier**: Packet verification logic
- **MapLoader**: BPF map management
- **Packet**: Packet creation/parsing

### 4. Honeypot

**Location**: `internal/honeypot/`

**Components**:
- **Honeypot**: Main honeypot server
- **Handlers**: Protocol handlers (SSH, MySQL, etc.)
- **Filesystem**: Fake filesystem for deception

### 5. Dashboard

**Location**: `internal/dashboard/`

**Components**:
- **Dashboard**: Terminal UI manager
- **Widgets**: UI components
- **Event Loop**: Log processing and display

### 6. Logger

**Location**: `internal/logger/`

**Components**:
- **Manager**: Log routing (dashboard/ELK)
- **Event**: Structured event types
- **Exporter**: ELK integration

---

## Data Flow

### SPA Authentication Flow

```
1. Client generates SPA packet
   └─▶ TOTP + Timestamp + Signature

2. Client sends UDP packet to port 1337
   └─▶ Network Interface

3. XDP program receives packet
   └─▶ Checks if it's SPA packet
   └─▶ Passes to user-space (XDP_PASS)

4. User-space handler receives packet
   └─▶ Parses packet
   └─▶ Verifies signature
   └─▶ Validates TOTP
   └─▶ Checks replay protection

5. Handler whitelists IP in BPF map
   └─▶ Updates spa_whitelist map
   └─▶ Sets expiry timestamp

6. Client connects to protected port
   └─▶ XDP program checks whitelist
   └─▶ Allows connection (XDP_PASS)
```

### Attack Traffic Flow

```
1. Attacker scans port 22
   └─▶ Network Interface

2. XDP program receives packet
   └─▶ Checks if port is critical
   └─▶ Checks if IP is whitelisted
   └─▶ IP not whitelisted → DROP

3. Attacker scans fake port (e.g., 3389)
   └─▶ XDP program detects fake port
   └─▶ Redirects to honeypot (XDP_REDIRECT)

4. Honeypot receives connection
   └─▶ Logs connection
   └─▶ Responds with fake service
   └─▶ Captures attacker behavior
```

---

## eBPF Programs

### XDP Program (Ingress)

**Hook Point**: Network interface driver

**Processing Order**:
1. Parse Ethernet header
2. Parse IP header
3. Check for SPA packet (UDP port 1337)
4. Check whitelist for critical ports
5. Check for fake ports (redirect to honeypot)
6. Apply OS fingerprint mutation
7. Return action (PASS, DROP, REDIRECT)

**BPF Maps Used**:
- `spa_whitelist`: IP → expiry timestamp
- `spa_auth_success`: Authentication counter
- `spa_auth_failed`: Failed authentication counter
- `redirect_stats`: Redirect statistics

### TC Egress Program

**Hook Point**: Traffic Control egress

**Processing**:
1. Parse packet payload
2. Scan for sensitive data patterns
3. Block if pattern detected
4. Log blocked attempts

**BPF Maps Used**:
- `egress_blocks`: Block counter
- `dlp_patterns`: DLP patterns (future)

---

## User-Space Components

### Agent Lifecycle

```
1. Initialize
   └─▶ Detect network interface
   └─▶ Load eBPF programs
   └─▶ Initialize logger

2. Start
   └─▶ Attach XDP program
   └─▶ Attach TC program (optional)
   └─▶ Start SPA handler
   └─▶ Start honeypot
   └─▶ Start dashboard (if enabled)

3. Run
   └─▶ Process logs
   └─▶ Update statistics
   └─▶ Handle signals

4. Shutdown
   └─▶ Detach eBPF programs
   └─▶ Close connections
   └─▶ Cleanup resources
```

### SPA Handler

**Goroutines**:
- **Main goroutine**: UDP listener
- **Packet processor**: Verify and whitelist IPs
- **Map updater**: Update BPF maps

**Channels**:
- `logChan`: Log messages
- `stopChan`: Shutdown signal

### Honeypot

**Components**:
- **Listener**: Accept connections on fake ports
- **Handlers**: Protocol-specific handlers
- **Filesystem**: Fake filesystem for deception

---

## Design Principles

### 1. Kernel-First Processing

- Maximum performance (line rate)
- Minimal latency
- Early packet filtering

### 2. Zero-Trust Architecture

- All access requires authentication
- No default allow rules
- Cryptographic verification

### 3. Defense in Depth

- Multiple layers of protection
- Deception at multiple levels
- Comprehensive logging

### 4. Centralized Configuration

- Single source of truth (Go code)
- Automatic code generation
- No manual synchronization

### 5. Modular Design

- Clear separation of concerns
- Reusable components
- Easy to extend

---

## Performance Characteristics

### Throughput

- **XDP Processing**: Line rate (10Gbps+)
- **SPA Verification**: <1ms per packet
- **Honeypot Response**: <10ms

### Resource Usage

- **Memory**: ~50MB (user-space) + ~10MB (eBPF maps)
- **CPU**: <5% on idle, <20% under attack
- **Network**: Minimal overhead (<1%)

### Scalability

- **Concurrent Connections**: 10,000+
- **Whitelisted IPs**: 100 (configurable)
- **Honeypot Sessions**: 1,000+

---

## Security Considerations

### Attack Surface

- **eBPF Programs**: Verified by kernel verifier
- **User-Space**: Standard Go security practices
- **Network**: Encrypted key distribution

### Threat Model

**Protected Against**:
- Port scanning
- Brute force attacks
- Reconnaissance
- Data exfiltration

**Not Protected Against**:
- Physical access
- Kernel exploits
- Compromised keys

---

## Extension Points

### Adding New Ports

1. Edit `internal/config/ports.go`
2. Run `make generate-config`
3. Rebuild

### Adding New Honeypot Protocol

1. Create handler in `internal/honeypot/`
2. Register in honeypot server
3. Add to fake ports list

### Custom DLP Patterns

1. Define patterns in `internal/config/constants.go`
2. Update eBPF program
3. Rebuild

---

**Related Documentation**:
- [Configuration Guide](configuration.md)
- [Development Guide](development.md)
- [API Reference](api.md)

