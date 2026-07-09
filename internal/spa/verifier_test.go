package spa

import (
	"net"
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"

	"phantom-grid/internal/config"
)

func TestNewVerifier(t *testing.T) {
	spaConfig := config.DefaultDynamicSPAConfig()
	verifier := NewVerifier(spaConfig)

	if verifier == nil {
		t.Fatal("NewVerifier returned nil")
	}

	if verifier.spaConfig == nil {
		t.Fatal("Verifier config is nil")
	}
}

func TestVerifyPacket_AsymmetricMode_Valid(t *testing.T) {
	// Generate key pair
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}

	// Create TOTP secret
	totpSecret := make([]byte, 32)
	rand.Read(totpSecret)

	// Create valid packet
	packetData, err := CreateAsymmetricPacket(privateKey, totpSecret, 30, true, net.ParseIP("192.168.1.100"))
	if err != nil {
		t.Fatalf("Failed to create packet: %v", err)
	}

	// Configure verifier
	spaConfig := config.DefaultDynamicSPAConfig()
	spaConfig.Mode = config.SPAModeAsymmetric
	spaConfig.PublicKey = publicKey
	spaConfig.TOTPSecret = totpSecret
	spaConfig.TOTPTimeStep = 30
	spaConfig.TOTPTolerance = 1

	verifier := NewVerifier(spaConfig)

	// Verify packet
	valid, err := verifier.VerifyPacket(packetData, net.ParseIP("192.168.1.100"))
	if err != nil {
		t.Fatalf("Verification failed with error: %v", err)
	}

	if !valid {
		t.Error("Valid packet was rejected")
	}
}

func TestVerifyPacket_AsymmetricMode_InvalidSignature(t *testing.T) {
	// Generate key pair
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}

	// Create TOTP secret
	totpSecret := make([]byte, 32)
	rand.Read(totpSecret)

	// Create valid packet
	packetData, err := CreateAsymmetricPacket(privateKey, totpSecret, 30, true, net.ParseIP("192.168.1.100"))
	if err != nil {
		t.Fatalf("Failed to create packet: %v", err)
	}

	// Corrupt signature (use wrong public key)
	wrongPublicKey, _, _ := ed25519.GenerateKey(rand.Reader)

	// Configure verifier with wrong public key
	spaConfig := config.DefaultDynamicSPAConfig()
	spaConfig.Mode = config.SPAModeAsymmetric
	spaConfig.PublicKey = wrongPublicKey
	spaConfig.TOTPSecret = totpSecret
	spaConfig.TOTPTimeStep = 30
	spaConfig.TOTPTolerance = 1

	verifier := NewVerifier(spaConfig)

	// Verify packet - should fail
	valid, err := verifier.VerifyPacket(packetData, net.ParseIP("192.168.1.100"))
	if err == nil {
		t.Error("Expected error for invalid signature")
	}

	if valid {
		t.Error("Invalid packet was accepted")
	}
}

func TestVerifyPacket_AsymmetricMode_InvalidTOTP(t *testing.T) {
	// Generate key pair
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}

	// Create TOTP secret
	totpSecret := make([]byte, 32)
	rand.Read(totpSecret)

	// Create valid packet
	packetData, err := CreateAsymmetricPacket(privateKey, totpSecret, 30, true, net.ParseIP("192.168.1.100"))
	if err != nil {
		t.Fatalf("Failed to create packet: %v", err)
	}

	// Use different TOTP secret
	wrongTOTPSecret := make([]byte, 32)
	rand.Read(wrongTOTPSecret)

	// Configure verifier with wrong TOTP secret
	spaConfig := config.DefaultDynamicSPAConfig()
	spaConfig.Mode = config.SPAModeAsymmetric
	spaConfig.PublicKey = publicKey
	spaConfig.TOTPSecret = wrongTOTPSecret // Wrong secret
	spaConfig.TOTPTimeStep = 30
	spaConfig.TOTPTolerance = 1

	verifier := NewVerifier(spaConfig)

	// Verify packet - should fail
	valid, err := verifier.VerifyPacket(packetData, net.ParseIP("192.168.1.100"))
	if err == nil {
		t.Error("Expected error for invalid TOTP")
	}

	if valid {
		t.Error("Invalid TOTP was accepted")
	}
}

func TestVerifyPacket_DynamicMode_Valid(t *testing.T) {
	// Create secrets
	hmacSecret := make([]byte, 32)
	totpSecret := make([]byte, 32)
	rand.Read(hmacSecret)
	rand.Read(totpSecret)

	// Create valid packet
	packetData, err := CreateDynamicPacket(hmacSecret, totpSecret, 30, true, net.ParseIP("192.168.1.100"))
	if err != nil {
		t.Fatalf("Failed to create packet: %v", err)
	}

	// Configure verifier
	spaConfig := config.DefaultDynamicSPAConfig()
	spaConfig.Mode = config.SPAModeDynamic
	spaConfig.HMACSecret = hmacSecret
	spaConfig.TOTPSecret = totpSecret
	spaConfig.TOTPTimeStep = 30
	spaConfig.TOTPTolerance = 1

	verifier := NewVerifier(spaConfig)

	// Verify packet
	valid, err := verifier.VerifyPacket(packetData, net.ParseIP("192.168.1.100"))
	if err != nil {
		t.Fatalf("Verification failed with error: %v", err)
	}

	if !valid {
		t.Error("Valid packet was rejected")
	}
}

func TestVerifyPacket_DynamicMode_InvalidHMAC(t *testing.T) {
	// Create secrets
	hmacSecret := make([]byte, 32)
	totpSecret := make([]byte, 32)
	rand.Read(hmacSecret)
	rand.Read(totpSecret)

	// Create valid packet
	packetData, err := CreateDynamicPacket(hmacSecret, totpSecret, 30, true, net.ParseIP("192.168.1.100"))
	if err != nil {
		t.Fatalf("Failed to create packet: %v", err)
	}

	// Use wrong HMAC secret
	wrongHMACSecret := make([]byte, 32)
	rand.Read(wrongHMACSecret)

	// Configure verifier with wrong HMAC secret
	spaConfig := config.DefaultDynamicSPAConfig()
	spaConfig.Mode = config.SPAModeDynamic
	spaConfig.HMACSecret = wrongHMACSecret // Wrong secret
	spaConfig.TOTPSecret = totpSecret
	spaConfig.TOTPTimeStep = 30
	spaConfig.TOTPTolerance = 1

	verifier := NewVerifier(spaConfig)

	// Verify packet - should fail
	valid, err := verifier.VerifyPacket(packetData, net.ParseIP("192.168.1.100"))
	if err == nil {
		t.Error("Expected error for invalid HMAC")
	}

	if valid {
		t.Error("Invalid HMAC was accepted")
	}
}

func TestVerifyPacket_InvalidVersion(t *testing.T) {
	// Create a packet with invalid version
	invalidPacket := make([]byte, 100)
	invalidPacket[0] = 99 // Invalid version

	spaConfig := config.DefaultDynamicSPAConfig()
	verifier := NewVerifier(spaConfig)

	// Verify packet - should fail
	valid, err := verifier.VerifyPacket(invalidPacket, net.ParseIP("192.168.1.100"))
	if err == nil {
		t.Error("Expected error for invalid version")
	}

	if valid {
		t.Error("Invalid version was accepted")
	}
}

func TestVerifyPacket_OldTimestamp(t *testing.T) {
	// Generate key pair
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}

	// Create TOTP secret
	totpSecret := make([]byte, 32)
	rand.Read(totpSecret)

	// Create packet with old timestamp (manually construct)
	oldTimestamp := time.Now().Unix() - 400 // 400 seconds ago (more than 5 minutes)
	packet := make([]byte, SPAPacketHeaderSizeV2)
	packet[0] = 1 // Version
	packet[1] = 2 // Mode: Asymmetric
	// Set old timestamp
	packet[2] = byte(oldTimestamp >> 56)
	packet[3] = byte(oldTimestamp >> 48)
	packet[4] = byte(oldTimestamp >> 40)
	packet[5] = byte(oldTimestamp >> 32)
	packet[6] = byte(oldTimestamp >> 24)
	packet[7] = byte(oldTimestamp >> 16)
	packet[8] = byte(oldTimestamp >> 8)
	packet[9] = byte(oldTimestamp)

	// Generate TOTP for old timestamp
	totp := TOTP(totpSecret, 30, oldTimestamp)
	packet[10] = byte(totp >> 24)
	packet[11] = byte(totp >> 16)
	packet[12] = byte(totp >> 8)
	packet[13] = byte(totp)

	// Add padding and signature
	padding := make([]byte, 16)
	rand.Read(padding)
	packet = append(packet, padding...)

	signature := ed25519.Sign(privateKey, packet)
	packet = append(packet, signature...)

	// Configure verifier
	spaConfig := config.DefaultDynamicSPAConfig()
	spaConfig.Mode = config.SPAModeAsymmetric
	spaConfig.PublicKey = publicKey
	spaConfig.TOTPSecret = totpSecret
	spaConfig.TOTPTimeStep = 30
	spaConfig.TOTPTolerance = 1

	verifier := NewVerifier(spaConfig)

	// Verify packet - should fail due to old timestamp
	valid, err := verifier.VerifyPacket(packet, net.ParseIP("192.168.1.100"))
	if err == nil {
		t.Error("Expected error for old timestamp")
	}

	if valid {
		t.Error("Old timestamp was accepted")
	}
}

func TestVerifyPacket_TooShort(t *testing.T) {
	// Create a packet that's too short
	shortPacket := make([]byte, 10)

	spaConfig := config.DefaultDynamicSPAConfig()
	verifier := NewVerifier(spaConfig)

	// Verify packet - should fail
	valid, err := verifier.VerifyPacket(shortPacket, net.ParseIP("192.168.1.100"))
	if err == nil {
		t.Error("Expected error for too short packet")
	}

	if valid {
		t.Error("Too short packet was accepted")
	}
}

func TestVerifyPacket_MissingPublicKey(t *testing.T) {
	// Generate key pair
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}

	// Create TOTP secret
	totpSecret := make([]byte, 32)
	rand.Read(totpSecret)

	// Create valid packet
	packetData, err := CreateAsymmetricPacket(privateKey, totpSecret, 30, true, net.ParseIP("192.168.1.100"))
	if err != nil {
		t.Fatalf("Failed to create packet: %v", err)
	}

	// Configure verifier without public key
	spaConfig := config.DefaultDynamicSPAConfig()
	spaConfig.Mode = config.SPAModeAsymmetric
	spaConfig.PublicKey = nil // Missing public key
	spaConfig.TOTPSecret = totpSecret
	spaConfig.TOTPTimeStep = 30
	spaConfig.TOTPTolerance = 1

	verifier := NewVerifier(spaConfig)

	// Verify packet - should fail
	valid, err := verifier.VerifyPacket(packetData, net.ParseIP("192.168.1.100"))
	if err == nil {
		t.Error("Expected error for missing public key")
	}

	if valid {
		t.Error("Missing public key was accepted")
	}
}

func TestVerifyTOTPOnly(t *testing.T) {
	// Create TOTP secret
	totpSecret := make([]byte, 32)
	rand.Read(totpSecret)

	// Generate TOTP
	totp := GenerateTOTP(totpSecret, 30)

	// Configure verifier
	spaConfig := config.DefaultDynamicSPAConfig()
	spaConfig.TOTPSecret = totpSecret
	spaConfig.TOTPTimeStep = 30
	spaConfig.TOTPTolerance = 1

	verifier := NewVerifier(spaConfig)

	// Verify TOTP only
	valid := verifier.VerifyTOTPOnly(totp)
	if !valid {
		t.Error("Valid TOTP was rejected")
	}

	// Test invalid TOTP
	invalidTOTP := uint32(123456)
	valid = verifier.VerifyTOTPOnly(invalidTOTP)
	if valid {
		t.Error("Invalid TOTP was accepted")
	}
}

func TestVerifyPacket_UnsupportedMode(t *testing.T) {
	// Create a packet with unsupported mode
	invalidPacket := make([]byte, 100)
	invalidPacket[0] = 1 // Valid version
	invalidPacket[1] = 99 // Invalid mode

	spaConfig := config.DefaultDynamicSPAConfig()
	spaConfig.Mode = config.SPAMode("unsupported")
	verifier := NewVerifier(spaConfig)

	// Verify packet - should fail
	valid, err := verifier.VerifyPacket(invalidPacket, net.ParseIP("192.168.1.100"))
	if err == nil {
		t.Error("Expected error for unsupported mode")
	}

	if valid {
		t.Error("Unsupported mode was accepted")
	}
}

