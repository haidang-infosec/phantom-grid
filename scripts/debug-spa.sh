#!/bin/bash
# Debug SPA authentication issues
# Usage: ./scripts/debug-spa.sh

echo "=== SPA Debugging Tool ==="
echo ""

# Check server configuration
echo "1. Checking Server Configuration..."
echo "-----------------------------------"
if [ -f "keys/spa_public.key" ]; then
    echo "✓ Public key exists: $(wc -c < keys/spa_public.key) bytes"
    xxd -l 16 keys/spa_public.key | head -1
else
    echo "✗ Public key NOT found!"
fi

if [ -f "keys/spa_private.key" ]; then
    echo "✓ Private key exists: $(wc -c < keys/spa_private.key) bytes"
else
    echo "✗ Private key NOT found!"
fi

if [ -f "keys/totp_secret.txt" ]; then
    echo "✓ TOTP secret exists: $(wc -c < keys/totp_secret.txt) bytes"
    echo "  Secret preview: $(head -c 20 keys/totp_secret.txt)..."
else
    echo "✗ TOTP secret NOT found!"
fi

echo ""
echo "2. Checking Network..."
echo "-----------------------------------"
if command -v netstat &> /dev/null; then
    echo "Port 1337 status:"
    netstat -tulpn 2>/dev/null | grep 1337 || echo "  Port 1337 not listening"
else
    echo "netstat not available"
fi

echo ""
echo "3. Checking eBPF Programs..."
echo "-----------------------------------"
if command -v bpftool &> /dev/null; then
    echo "eBPF programs:"
    sudo bpftool prog list 2>/dev/null | grep -i phantom || echo "  No phantom programs found"
    echo ""
    echo "eBPF maps:"
    sudo bpftool map list 2>/dev/null | grep -E "whitelist|spa" || echo "  No SPA maps found"
else
    echo "bpftool not available"
fi

echo ""
echo "4. Checking Logs..."
echo "-----------------------------------"
if [ -f "logs/audit.json" ]; then
    echo "Recent SPA logs:"
    tail -20 logs/audit.json | grep -i spa || echo "  No SPA logs found"
else
    echo "Log file not found"
fi

echo ""
echo "5. Common Issues Checklist..."
echo "-----------------------------------"
echo "[ ] Keys match between server and client"
echo "[ ] TOTP secret is identical on both sides"
echo "[ ] Time is synchronized (check with: ntpdate -q pool.ntp.org)"
echo "[ ] Firewall allows UDP port 1337"
echo "[ ] Agent is running with correct mode: -spa-mode asymmetric"
echo "[ ] Client uses matching mode: -mode asymmetric"

echo ""
echo "=== Debug Complete ==="

