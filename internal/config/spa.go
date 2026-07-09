package config

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"os"
	"path/filepath"
)

// SPAMode defines the SPA authentication mode
type SPAMode string

const (
	SPAModeStatic    SPAMode = "static"    // Legacy static token (backward compatible)
	SPAModeDynamic   SPAMode = "dynamic"  // Dynamic SPA with TOTP + HMAC
	SPAModeAsymmetric SPAMode = "asymmetric" // Dynamic SPA with TOTP + Ed25519 (recommended)
)

// DynamicSPAConfig holds configuration for dynamic SPA
type DynamicSPAConfig struct {
	Mode SPAMode // SPA authentication mode

	// TOTP Configuration
	TOTPTimeStep    int    // Time step in seconds (default: 30)
	TOTPTolerance   int    // Time tolerance in steps (default: 1, allows ±30s)
	TOTPSecret      []byte // Shared secret for TOTP (32 bytes recommended)

	// Ed25519 Configuration (for asymmetric mode)
	PublicKey  ed25519.PublicKey  // Server public key (32 bytes)
	PrivateKey ed25519.PrivateKey // Client private key (64 bytes) - only for key generation

	// HMAC Configuration (for dynamic mode)
	HMACSecret []byte // Shared secret for HMAC-SHA256 (32 bytes)

	// Anti-Replay Configuration
	ReplayWindowSeconds int // Replay protection window (default: 60)
	MaxReplayEntries    int // Maximum replay entries in LRU map (default: 1000)

	// Packet Obfuscation
	EnableObfuscation bool // Enable binary packet obfuscation
	ObfuscationKey    []byte // Key for packet obfuscation (optional)
}

// DefaultDynamicSPAConfig returns default dynamic SPA configuration
func DefaultDynamicSPAConfig() *DynamicSPAConfig {
	// Generate default TOTP secret
	totpSecret := make([]byte, 32)
	if _, err := rand.Read(totpSecret); err != nil {
		// Fallback to default secret
		totpSecret = []byte("PHANTOM_GRID_TOTP_SECRET_2025_DEFAULT")
	}

	return &DynamicSPAConfig{
		Mode:               SPAModeAsymmetric,
		TOTPTimeStep:       30,
		TOTPTolerance:      1,
		TOTPSecret:         totpSecret,
		ReplayWindowSeconds: 60,
		MaxReplayEntries:    1000,
		EnableObfuscation:   true,
	}
}

// GenerateEd25519Keys generates a new Ed25519 key pair
func GenerateEd25519Keys() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	return ed25519.GenerateKey(rand.Reader)
}

// LoadKeysFromFile loads Ed25519 keys from files
// If publicKeyPath is empty, only private key will be loaded
// If privateKeyPath is empty, only public key will be loaded
func LoadKeysFromFile(publicKeyPath, privateKeyPath string) (ed25519.PublicKey, ed25519.PrivateKey, error) {
	var publicKey ed25519.PublicKey
	var privateKey ed25519.PrivateKey

	// Load public key if path is provided
	if publicKeyPath != "" {
		publicKeyData, err := os.ReadFile(publicKeyPath)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to read public key: %w", err)
		}
		// Remove any whitespace/newlines
		publicKeyData = bytes.TrimSpace(publicKeyData)
		if len(publicKeyData) != ed25519.PublicKeySize {
			return nil, nil, fmt.Errorf("invalid public key size: expected %d, got %d", ed25519.PublicKeySize, len(publicKeyData))
		}
		publicKey = ed25519.PublicKey(publicKeyData)
	}

	// Load private key if path is provided
	if privateKeyPath != "" {
		privateKeyData, err := os.ReadFile(privateKeyPath)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to read private key: %w", err)
		}
		// Remove any whitespace/newlines
		privateKeyData = bytes.TrimSpace(privateKeyData)
		if len(privateKeyData) != ed25519.PrivateKeySize {
			return nil, nil, fmt.Errorf("invalid private key size: expected %d, got %d", ed25519.PrivateKeySize, len(privateKeyData))
		}
		privateKey = ed25519.PrivateKey(privateKeyData)

		// If public key was not loaded, derive it from private key
		if publicKey == nil {
			publicKey = privateKey.Public().(ed25519.PublicKey)
		}
	}

	// At least one key must be loaded
	if publicKey == nil && privateKey == nil {
		return nil, nil, fmt.Errorf("at least one key path must be provided")
	}

	return publicKey, privateKey, nil
}

// LoadPrivateKeyFromFile loads only the private key from a file
// This is a convenience function for clients that only need the private key
func LoadPrivateKeyFromFile(privateKeyPath string) (ed25519.PrivateKey, error) {
	_, privateKey, err := LoadKeysFromFile("", privateKeyPath)
	return privateKey, err
}

// SaveKeysToFile saves Ed25519 keys to files
func SaveKeysToFile(publicKey ed25519.PublicKey, privateKey ed25519.PrivateKey, keyDir string) error {
	if err := os.MkdirAll(keyDir, 0700); err != nil {
		return fmt.Errorf("failed to create key directory: %w", err)
	}

	publicKeyPath := filepath.Join(keyDir, "spa_public.key")
	privateKeyPath := filepath.Join(keyDir, "spa_private.key")

	if err := os.WriteFile(publicKeyPath, publicKey, 0644); err != nil {
		return fmt.Errorf("failed to write public key: %w", err)
	}

	if err := os.WriteFile(privateKeyPath, privateKey, 0600); err != nil {
		return fmt.Errorf("failed to write private key: %w", err)
	}

	return nil
}

// GetSPAMode returns the current SPA mode
func GetSPAMode() SPAMode {
	// Check environment variable first
	if mode := os.Getenv("SPA_MODE"); mode != "" {
		switch SPAMode(mode) {
		case SPAModeStatic, SPAModeDynamic, SPAModeAsymmetric:
			return SPAMode(mode)
		}
	}
	// Default to asymmetric for new installations
	return SPAModeAsymmetric
}


