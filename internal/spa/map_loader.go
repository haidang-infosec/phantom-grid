package spa

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"

	"github.com/cilium/ebpf"

	"phantom-grid/internal/config"
)

// MapLoader loads SPA configuration into BPF maps
type MapLoader struct {
	whitelistMap    *ebpf.Map
	replayMap       *ebpf.Map
	totpSecretMap   *ebpf.Map
	hmacSecretMap   *ebpf.Map
	configMap       *ebpf.Map
}

// NewMapLoader creates a new SPA map loader
// Note: Maps must be from the dynamic SPA eBPF program
func NewMapLoader(whitelistMap, replayMap, totpSecretMap, hmacSecretMap, configMap *ebpf.Map) *MapLoader {
	return &MapLoader{
		whitelistMap:  whitelistMap,
		replayMap:     replayMap,
		totpSecretMap: totpSecretMap,
		hmacSecretMap: hmacSecretMap,
		configMap:     configMap,
	}
}

// LoadConfiguration loads SPA configuration into BPF maps
func (ml *MapLoader) LoadConfiguration(spaConfig *config.DynamicSPAConfig) error {
	if ml.configMap == nil {
		return fmt.Errorf("config map not available")
	}

	// Load TOTP secret
	if ml.totpSecretMap != nil && len(spaConfig.TOTPSecret) > 0 {
		if err := ml.loadTOTPSecret(spaConfig.TOTPSecret); err != nil {
			return fmt.Errorf("failed to load TOTP secret: %w", err)
		}
	}

	// Load HMAC secret (for dynamic mode)
	if ml.hmacSecretMap != nil && len(spaConfig.HMACSecret) > 0 {
		if err := ml.loadHMACSecret(spaConfig.HMACSecret); err != nil {
			return fmt.Errorf("failed to load HMAC secret: %w", err)
		}
	}

	// Load configuration values
	configValues := map[uint32]uint32{
		0: uint32(spaConfig.TOTPTimeStep),    // TOTP time step
		1: uint32(spaConfig.TOTPTolerance),  // TOTP tolerance
		2: uint32(spaConfig.ReplayWindowSeconds), // Replay window
		3: uint32(ml.getSPAModeValue(spaConfig.Mode)), // SPA mode
	}

	for key, value := range configValues {
		if err := ml.configMap.Put(key, value); err != nil {
			return fmt.Errorf("failed to set config key %d: %w", key, err)
		}
	}

	return nil
}

// WhitelistIP adds an IP address to the whitelist
func (ml *MapLoader) WhitelistIP(ip net.IP, durationSeconds int) error {
	if ml.whitelistMap == nil {
		return fmt.Errorf("whitelist map not available")
	}

	// Convert IP to network byte order
	ipv4 := ip.To4()
	if ipv4 == nil {
		return fmt.Errorf("invalid IPv4 address: %s", ip.String())
	}

	ipUint32 := binary.BigEndian.Uint32(ipv4)

	// Calculate absolute expiry timestamp (nanoseconds since boot)
	// eBPF uses bpf_ktime_get_ns() which returns nanoseconds since system boot
	// We need to estimate the current boot time to calculate expiry correctly
	
	// Read /proc/uptime to get system uptime in seconds
	uptimeSeconds, err := getUptimeSeconds()
	if err != nil {
		// Fallback: use a large base time if we can't read uptime
		// This ensures expiry is in the future, but may cause issues with expiration
		baseTime := uint64(1000000000000000000) // 10^18 nanoseconds
		durationNs := uint64(durationSeconds) * 1000000000
		expiry := baseTime + durationNs
		return ml.whitelistMap.Put(ipUint32, expiry)
	}
	
	// Convert uptime to nanoseconds and add duration
	uptimeNs := uint64(uptimeSeconds * 1e9)
	durationNs := uint64(durationSeconds) * 1000000000
	expiry := uptimeNs + durationNs
	
	// Add a small buffer (1 second) to account for timing differences
	expiry += 1000000000

	return ml.whitelistMap.Put(ipUint32, expiry)
}

// getUptimeSeconds reads system uptime from /proc/uptime
func getUptimeSeconds() (float64, error) {
	file, err := os.Open("/proc/uptime")
	if err != nil {
		return 0, err
	}
	defer file.Close()

	data, err := io.ReadAll(file)
	if err != nil {
		return 0, err
	}

	// /proc/uptime format: "uptime_seconds idle_seconds"
	fields := strings.Fields(string(data))
	if len(fields) == 0 {
		return 0, fmt.Errorf("invalid /proc/uptime format")
	}

	uptime, err := strconv.ParseFloat(fields[0], 64)
	if err != nil {
		return 0, err
	}

	return uptime, nil
}

// RemoveWhitelistIP removes an IP from the whitelist
func (ml *MapLoader) RemoveWhitelistIP(ip net.IP) error {
	if ml.whitelistMap == nil {
		return fmt.Errorf("whitelist map not available")
	}

	ipv4 := ip.To4()
	if ipv4 == nil {
		return fmt.Errorf("invalid IPv4 address: %s", ip.String())
	}

	ipUint32 := binary.BigEndian.Uint32(ipv4)
	return ml.whitelistMap.Delete(ipUint32)
}

// loadTOTPSecret loads TOTP secret into BPF map
func (ml *MapLoader) loadTOTPSecret(secret []byte) error {
	if len(secret) > 32 {
		return fmt.Errorf("TOTP secret too long: %d bytes (max 32)", len(secret))
	}

	// Load secret byte by byte into array map
	for i := 0; i < len(secret) && i < 32; i++ {
		key := uint32(i)
		value := secret[i]
		if err := ml.totpSecretMap.Put(key, value); err != nil {
			return fmt.Errorf("failed to set TOTP secret byte %d: %w", i, err)
		}
	}

	return nil
}

// loadHMACSecret loads HMAC secret into BPF map
func (ml *MapLoader) loadHMACSecret(secret []byte) error {
	if len(secret) > 32 {
		return fmt.Errorf("HMAC secret too long: %d bytes (max 32)", len(secret))
	}

	// Load secret byte by byte into array map
	for i := 0; i < len(secret) && i < 32; i++ {
		key := uint32(i)
		value := secret[i]
		if err := ml.hmacSecretMap.Put(key, value); err != nil {
			return fmt.Errorf("failed to set HMAC secret byte %d: %w", i, err)
		}
	}

	return nil
}

// getSPAModeValue converts SPAMode to uint32 for BPF map
func (ml *MapLoader) getSPAModeValue(mode config.SPAMode) uint32 {
	switch mode {
	case config.SPAModeStatic:
		return 0
	case config.SPAModeDynamic:
		return 1
	case config.SPAModeAsymmetric:
		return 2
	default:
		return 0 // Default to static
	}
}

