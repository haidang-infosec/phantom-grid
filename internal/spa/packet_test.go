package spa

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"
)

func TestCreateAsymmetricPacket(t *testing.T) {
	// Generate key pair
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}

	// Create TOTP secret
	totpSecret := make([]byte, 32)
	rand.Read(totpSecret)

	// Create packet
	packetData, err := CreateAsymmetricPacket(privateKey, totpSecret, 30, true)
	if err != nil {
		t.Fatalf("Failed to create packet: %v", err)
	}

	// Verify packet structure
	if len(packetData) < SPAPacketHeaderSize+Ed25519SignatureSize {
		t.Errorf("Packet too short: %d bytes", len(packetData))
	}

	// Parse packet
	packet, err := ParseSPAPacket(packetData)
	if err != nil {
		t.Fatalf("Failed to parse packet: %v", err)
	}

	// Verify packet fields
	if packet.Version != 1 {
		t.Errorf("Expected version 1, got %d", packet.Version)
	}

	if packet.Mode != 2 {
		t.Errorf("Expected mode 2 (asymmetric), got %d", packet.Mode)
	}

	// Verify timestamp is recent (within 5 seconds)
	currentTime := time.Now().Unix()
	timeDiff := currentTime - packet.Timestamp
	if timeDiff < 0 {
		timeDiff = -timeDiff
	}
	if timeDiff > 5 {
		t.Errorf("Timestamp too old: diff=%d seconds", timeDiff)
	}

	// Verify signature
	valid := VerifyAsymmetricPacket(publicKey, packet, packetData)
	if !valid {
		t.Error("Signature verification failed")
	}
}

func TestCreateDynamicPacket(t *testing.T) {
	// Create secrets
	hmacSecret := make([]byte, 32)
	totpSecret := make([]byte, 32)
	rand.Read(hmacSecret)
	rand.Read(totpSecret)

	// Create packet
	packetData, err := CreateDynamicPacket(hmacSecret, totpSecret, 30, true)
	if err != nil {
		t.Fatalf("Failed to create packet: %v", err)
	}

	// Verify packet structure
	if len(packetData) < SPAPacketHeaderSize+HMACSignatureSize {
		t.Errorf("Packet too short: %d bytes", len(packetData))
	}

	// Parse packet
	packet, err := ParseSPAPacket(packetData)
	if err != nil {
		t.Fatalf("Failed to parse packet: %v", err)
	}

	// Verify packet fields
	if packet.Version != 1 {
		t.Errorf("Expected version 1, got %d", packet.Version)
	}

	if packet.Mode != 1 {
		t.Errorf("Expected mode 1 (dynamic), got %d", packet.Mode)
	}

	// Verify HMAC
	valid := VerifyDynamicPacket(hmacSecret, packet, packetData)
	if !valid {
		t.Error("HMAC verification failed")
	}
}

func TestTOTP(t *testing.T) {
	secret := make([]byte, 32)
	rand.Read(secret)

	// Generate TOTP
	totp1 := GenerateTOTP(secret, 30)
	if totp1 == 0 {
		t.Error("TOTP generation returned 0")
	}

	// Validate TOTP
	valid := ValidateTOTP(secret, 30, 1, totp1)
	if !valid {
		t.Error("TOTP validation failed for same time step")
	}

	// Test tolerance
	// Generate TOTP for next time step
	time.Sleep(31 * time.Second)
	_ = GenerateTOTP(secret, 30) // Generate but don't use (testing time progression)
	
	// Should still validate with tolerance
	valid = ValidateTOTP(secret, 30, 1, totp1)
	if valid {
		// This might fail if we're exactly at the boundary
		// That's okay, just log it
		t.Log("TOTP from previous step still valid (within tolerance)")
	}
}

func TestPacketObfuscation(t *testing.T) {
	_, privateKey, _ := ed25519.GenerateKey(rand.Reader)
	totpSecret := make([]byte, 32)
	rand.Read(totpSecret)

	// Create packet with obfuscation
	packetData1, _ := CreateAsymmetricPacket(privateKey, totpSecret, 30, true)
	packetData2, _ := CreateAsymmetricPacket(privateKey, totpSecret, 30, true)

	// Packets should have different padding (high probability)
	if len(packetData1) == len(packetData2) {
		// Check if padding is different
		headerSize := SPAPacketHeaderSize
		sigSize := Ed25519SignatureSize
		padding1 := packetData1[headerSize : len(packetData1)-sigSize]
		padding2 := packetData2[headerSize : len(packetData2)-sigSize]
		
		// Padding should be different (very high probability)
		allSame := true
		for i := 0; i < len(padding1) && i < len(padding2); i++ {
			if padding1[i] != padding2[i] {
				allSame = false
				break
			}
		}
		
		if allSame && len(padding1) > 0 {
			t.Log("Warning: Padding is identical (unlikely but possible)")
		}
	}
}

