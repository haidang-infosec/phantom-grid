package spa

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"sync"
	"time"

	"phantom-grid/internal/config"
)

// Verifier verifies dynamic SPA packets
type Verifier struct {
	spaConfig *config.DynamicSPAConfig
	seenCache map[string]int64
	mu        sync.Mutex
}

// NewVerifier creates a new SPA packet verifier
func NewVerifier(spaConfig *config.DynamicSPAConfig) *Verifier {
	return &Verifier{
		spaConfig: spaConfig,
		seenCache: make(map[string]int64),
	}
}

// VerifyPacket verifies a received SPA packet
func (v *Verifier) VerifyPacket(packetData []byte, actualClientIP net.IP) (bool, error) {
	// Parse packet
	packet, err := ParseSPAPacket(packetData)
	if err != nil {
		return false, fmt.Errorf("failed to parse packet: %w", err)
	}

	// Check version
	if packet.Version != 1 && packet.Version != 2 {
		return false, fmt.Errorf("unsupported packet version: %d", packet.Version)
	}

	// Verify IP binding for V2
	if packet.Version == 2 {
		if packet.ClientIP == nil || actualClientIP == nil {
			return false, fmt.Errorf("missing client IP for V2 packet")
		}
		pIP := packet.ClientIP.To16()
		aIP := actualClientIP.To16()
		if pIP == nil || aIP == nil {
			return false, fmt.Errorf("invalid IP format")
		}
		for i := 0; i < 16; i++ {
			if pIP[i] != aIP[i] {
				return false, fmt.Errorf("IP hijacking detected: packet IP %s does not match sender IP %s", packet.ClientIP.String(), actualClientIP.String())
			}
		}
	}

	// Validate timestamp (prevent old packets)
	currentTime := time.Now().Unix()
	timeDiff := currentTime - packet.Timestamp
	if timeDiff < 0 {
		timeDiff = -timeDiff
	}

	// Allow ±5 minutes for clock skew
	maxTimeDiff := int64(300) // 5 minutes
	if timeDiff > maxTimeDiff {
		return false, fmt.Errorf("packet timestamp too old or too far in future: diff=%d seconds", timeDiff)
	}

	// Validate TOTP across all known secrets
	validTOTP := false
	if len(v.spaConfig.TOTPSecrets) > 0 {
		for _, secret := range v.spaConfig.TOTPSecrets {
			if ValidateTOTP(secret, v.spaConfig.TOTPTimeStep, v.spaConfig.TOTPTolerance, packet.TOTP) {
				validTOTP = true
				break
			}
		}
	} else if len(v.spaConfig.TOTPSecret) > 0 {
		// Fallback for single secret (legacy/client)
		validTOTP = ValidateTOTP(v.spaConfig.TOTPSecret, v.spaConfig.TOTPTimeStep, v.spaConfig.TOTPTolerance, packet.TOTP)
	}

	if !validTOTP {
		return false, fmt.Errorf("invalid TOTP")
	}

	// Verify signature based on mode
	switch v.spaConfig.Mode {
	case config.SPAModeAsymmetric:
		validSig := false
		if len(v.spaConfig.PublicKeys) > 0 {
			for _, pk := range v.spaConfig.PublicKeys {
				if VerifyAsymmetricPacket(pk, packet, packetData) {
					validSig = true
					break
				}
			}
		} else if len(v.spaConfig.PublicKey) > 0 {
			// Fallback
			validSig = VerifyAsymmetricPacket(v.spaConfig.PublicKey, packet, packetData)
		}

		if !validSig {
			return false, fmt.Errorf("invalid Ed25519 signature (no key matched)")
		}

	case config.SPAModeDynamic:
		validSig := false
		if len(v.spaConfig.HMACSecrets) > 0 {
			for _, hmacSecret := range v.spaConfig.HMACSecrets {
				if VerifyDynamicPacket(hmacSecret, packet, packetData) {
					validSig = true
					break
				}
			}
		} else if len(v.spaConfig.HMACSecret) > 0 {
			validSig = VerifyDynamicPacket(v.spaConfig.HMACSecret, packet, packetData)
		}

		if !validSig {
			return false, fmt.Errorf("invalid HMAC signature (no secret matched)")
		}

	default:
		return false, fmt.Errorf("unsupported SPA mode: %s", v.spaConfig.Mode)
	}

	// Replay Cache Check
	hash := sha256.Sum256(packetData)
	hashStr := hex.EncodeToString(hash[:])
	
	v.mu.Lock()
	defer v.mu.Unlock()
	
	// Clean up old entries occasionally
	if len(v.seenCache) > 1000 {
		for k, t := range v.seenCache {
			if currentTime-t > maxTimeDiff {
				delete(v.seenCache, k)
			}
		}
	}
	
	if _, exists := v.seenCache[hashStr]; exists {
		return false, fmt.Errorf("replay attack detected: packet already seen")
	}
	v.seenCache[hashStr] = currentTime

	return true, nil
}

// VerifyTOTPOnly verifies only the TOTP (for quick checks)
func (v *Verifier) VerifyTOTPOnly(totp uint32) bool {
	return ValidateTOTP(
		v.spaConfig.TOTPSecret,
		v.spaConfig.TOTPTimeStep,
		v.spaConfig.TOTPTolerance,
		totp,
	)
}

