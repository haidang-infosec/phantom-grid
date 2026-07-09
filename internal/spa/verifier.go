package spa

import (
	"fmt"
	"time"

	"phantom-grid/internal/config"
)

// Verifier verifies dynamic SPA packets
type Verifier struct {
	spaConfig *config.DynamicSPAConfig
}

// NewVerifier creates a new SPA packet verifier
func NewVerifier(spaConfig *config.DynamicSPAConfig) *Verifier {
	return &Verifier{
		spaConfig: spaConfig,
	}
}

// VerifyPacket verifies a received SPA packet
func (v *Verifier) VerifyPacket(packetData []byte) (bool, error) {
	// Parse packet
	packet, err := ParseSPAPacket(packetData)
	if err != nil {
		return false, fmt.Errorf("failed to parse packet: %w", err)
	}

	// Check version
	if packet.Version != 1 {
		return false, fmt.Errorf("unsupported packet version: %d", packet.Version)
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

	// Validate TOTP
	validTOTP := ValidateTOTP(
		v.spaConfig.TOTPSecret,
		v.spaConfig.TOTPTimeStep,
		v.spaConfig.TOTPTolerance,
		packet.TOTP,
	)

	if !validTOTP {
		return false, fmt.Errorf("invalid TOTP")
	}

	// Verify signature based on mode
	switch v.spaConfig.Mode {
	case config.SPAModeAsymmetric:
		if len(v.spaConfig.PublicKey) == 0 {
			return false, fmt.Errorf("public key not configured")
		}
		valid := VerifyAsymmetricPacket(v.spaConfig.PublicKey, packet, packetData)
		if !valid {
			return false, fmt.Errorf("invalid Ed25519 signature")
		}

	case config.SPAModeDynamic:
		if len(v.spaConfig.HMACSecret) == 0 {
			return false, fmt.Errorf("HMAC secret not configured")
		}
		valid := VerifyDynamicPacket(v.spaConfig.HMACSecret, packet, packetData)
		if !valid {
			return false, fmt.Errorf("invalid HMAC signature")
		}

	default:
		return false, fmt.Errorf("unsupported SPA mode: %s", v.spaConfig.Mode)
	}

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

