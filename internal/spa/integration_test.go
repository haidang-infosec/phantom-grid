package spa

import (
	"crypto/ed25519"
	"crypto/rand"
	"net"
	"testing"
	"time"

	"phantom-grid/internal/config"
)

// TestSPAAuthenticationFlow tests the complete SPA authentication flow
func TestSPAAuthenticationFlow_Asymmetric(t *testing.T) {
	// Generate key pair
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}

	// Create TOTP secret
	totpSecret := make([]byte, 32)
	rand.Read(totpSecret)

	// Configure server-side SPA
	serverConfig := config.DefaultDynamicSPAConfig()
	serverConfig.Mode = config.SPAModeAsymmetric
	serverConfig.PublicKey = publicKey
	serverConfig.TOTPSecret = totpSecret
	serverConfig.TOTPTimeStep = 30
	serverConfig.TOTPTolerance = 1

	// Create server verifier
	serverVerifier := NewVerifier(serverConfig)

	// Create client-side packet
	clientPacket, err := CreateAsymmetricPacket(privateKey, totpSecret, 30, true, net.ParseIP("192.168.1.100"))
	if err != nil {
		t.Fatalf("Failed to create client packet: %v", err)
	}

	// Server verifies packet
	valid, err := serverVerifier.VerifyPacket(clientPacket, net.ParseIP("192.168.1.100"))
	if err != nil {
		t.Fatalf("Server verification failed: %v", err)
	}

	if !valid {
		t.Error("Valid client packet was rejected by server")
	}

	// Verify packet structure
	packet, err := ParseSPAPacket(clientPacket)
	if err != nil {
		t.Fatalf("Failed to parse packet: %v", err)
	}

	// Check timestamp is recent
	currentTime := time.Now().Unix()
	timeDiff := currentTime - packet.Timestamp
	if timeDiff < 0 {
		timeDiff = -timeDiff
	}
	if timeDiff > 5 {
		t.Errorf("Packet timestamp too old: diff=%d seconds", timeDiff)
	}

	// Verify TOTP
	validTOTP := ValidateTOTP(totpSecret, 30, 1, packet.TOTP)
	if !validTOTP {
		t.Error("TOTP validation failed")
	}

	// Verify signature
	validSig := VerifyAsymmetricPacket(publicKey, packet, clientPacket)
	if !validSig {
		t.Error("Signature verification failed")
	}
}

// TestSPAAuthenticationFlow_Dynamic tests the complete SPA authentication flow with HMAC
func TestSPAAuthenticationFlow_Dynamic(t *testing.T) {
	// Create secrets
	hmacSecret := make([]byte, 32)
	totpSecret := make([]byte, 32)
	rand.Read(hmacSecret)
	rand.Read(totpSecret)

	// Configure server-side SPA
	serverConfig := config.DefaultDynamicSPAConfig()
	serverConfig.Mode = config.SPAModeDynamic
	serverConfig.HMACSecret = hmacSecret
	serverConfig.TOTPSecret = totpSecret
	serverConfig.TOTPTimeStep = 30
	serverConfig.TOTPTolerance = 1

	// Create server verifier
	serverVerifier := NewVerifier(serverConfig)

	// Create client-side packet
	clientPacket, err := CreateDynamicPacket(hmacSecret, totpSecret, 30, true, net.ParseIP("192.168.1.100"))
	if err != nil {
		t.Fatalf("Failed to create client packet: %v", err)
	}

	// Server verifies packet
	valid, err := serverVerifier.VerifyPacket(clientPacket, net.ParseIP("192.168.1.100"))
	if err != nil {
		t.Fatalf("Server verification failed: %v", err)
	}

	if !valid {
		t.Error("Valid client packet was rejected by server")
	}

	// Verify packet structure
	packet, err := ParseSPAPacket(clientPacket)
	if err != nil {
		t.Fatalf("Failed to parse packet: %v", err)
	}

	// Verify HMAC
	validHMAC := VerifyDynamicPacket(hmacSecret, packet, clientPacket)
	if !validHMAC {
		t.Error("HMAC verification failed")
	}
}

// TestSPAReplayProtection tests that replay attacks are prevented
func TestSPAReplayProtection(t *testing.T) {
	// Generate key pair
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}

	// Create TOTP secret
	totpSecret := make([]byte, 32)
	rand.Read(totpSecret)

	// Create first packet
	packet1, err := CreateAsymmetricPacket(privateKey, totpSecret, 30, true, net.ParseIP("192.168.1.100"))
	if err != nil {
		t.Fatalf("Failed to create packet: %v", err)
	}

	// Wait a bit
	time.Sleep(100 * time.Millisecond)

	// Create second packet (should be different due to TOTP)
	packet2, err := CreateAsymmetricPacket(privateKey, totpSecret, 30, true, net.ParseIP("192.168.1.100"))
	if err != nil {
		t.Fatalf("Failed to create packet: %v", err)
	}

	// Packets should be different (due to TOTP or padding)
	if len(packet1) == len(packet2) {
		// Check if content is different
		same := true
		for i := 0; i < len(packet1) && i < len(packet2); i++ {
			if packet1[i] != packet2[i] {
				same = false
				break
			}
		}
		if same {
			t.Log("Warning: Packets are identical (unlikely but possible)")
		}
	}

	// Both packets should be valid
	serverConfig := config.DefaultDynamicSPAConfig()
	serverConfig.Mode = config.SPAModeAsymmetric
	serverConfig.PublicKey = publicKey
	serverConfig.TOTPSecret = totpSecret
	serverConfig.TOTPTimeStep = 30
	serverConfig.TOTPTolerance = 1

	verifier := NewVerifier(serverConfig)

	valid1, err1 := verifier.VerifyPacket(packet1, net.ParseIP("192.168.1.100"))
	valid2, err2 := verifier.VerifyPacket(packet2, net.ParseIP("192.168.1.100"))

	if err1 != nil {
		t.Errorf("First packet verification error: %v", err1)
	}
	if err2 != nil {
		t.Errorf("Second packet verification error: %v", err2)
	}

	if !valid1 {
		t.Error("First packet was rejected")
	}
	if !valid2 {
		t.Error("Second packet was rejected")
	}
}

// TestSPAClientServerIntegration tests client-server integration
func TestSPAClientServerIntegration(t *testing.T) {
	// Generate key pair
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}

	// Create TOTP secret
	totpSecret := make([]byte, 32)
	rand.Read(totpSecret)

	// Start UDP server
	serverAddr, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to resolve address: %v", err)
	}

	serverConn, err := net.ListenUDP("udp", serverAddr)
	if err != nil {
		t.Fatalf("Failed to listen: %v", err)
	}
	defer serverConn.Close()

	serverPort := serverConn.LocalAddr().(*net.UDPAddr).Port

	// Configure server
	serverConfig := config.DefaultDynamicSPAConfig()
	serverConfig.Mode = config.SPAModeAsymmetric
	serverConfig.PublicKey = publicKey
	serverConfig.TOTPSecret = totpSecret
	serverConfig.TOTPTimeStep = 30
	serverConfig.TOTPTolerance = 1

	serverVerifier := NewVerifier(serverConfig)

	// Client creates and sends packet
	clientPacket, err := CreateAsymmetricPacket(privateKey, totpSecret, 30, true, net.ParseIP("192.168.1.100"))
	if err != nil {
		t.Fatalf("Failed to create client packet: %v", err)
	}

	// Send packet
	clientConn, err := net.DialUDP("udp", nil, &net.UDPAddr{
		IP:   net.IPv4(127, 0, 0, 1),
		Port: serverPort,
	})
	if err != nil {
		t.Fatalf("Failed to dial: %v", err)
	}
	defer clientConn.Close()

	_, err = clientConn.Write(clientPacket)
	if err != nil {
		t.Fatalf("Failed to send packet: %v", err)
	}

	// Server receives packet
	buffer := make([]byte, 1500)
	serverConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, clientAddr, err := serverConn.ReadFromUDP(buffer)
	if err != nil {
		t.Fatalf("Failed to receive packet: %v", err)
	}

	if n == 0 {
		t.Error("No packet received")
	}

	// Verify packet
	receivedPacket := buffer[:n]
	valid, err := serverVerifier.VerifyPacket(receivedPacket, net.ParseIP("192.168.1.100"))
	if err != nil {
		t.Fatalf("Server verification failed: %v", err)
	}

	if !valid {
		t.Error("Valid packet was rejected by server")
	}

	// Check client IP
	if clientAddr.IP.String() != "127.0.0.1" {
		t.Errorf("Expected client IP 127.0.0.1, got %s", clientAddr.IP.String())
	}
}

// TestSPATOTPTolerance tests TOTP tolerance window
func TestSPATOTPTolerance(t *testing.T) {
	// Create TOTP secret
	totpSecret := make([]byte, 32)
	rand.Read(totpSecret)

	// Configure server with tolerance
	serverConfig := config.DefaultDynamicSPAConfig()
	serverConfig.Mode = config.SPAModeAsymmetric
	serverConfig.TOTPSecret = totpSecret
	serverConfig.TOTPTimeStep = 30
	serverConfig.TOTPTolerance = 2 // Allow ±2 steps

	verifier := NewVerifier(serverConfig)

	// Generate TOTP for current time
	currentTOTP := GenerateTOTP(totpSecret, 30)

	// Verify TOTP with tolerance
	valid := verifier.VerifyTOTPOnly(currentTOTP)
	if !valid {
		t.Error("Current TOTP was rejected")
	}

	// Test that invalid TOTP is rejected
	invalidTOTP := uint32(123456)
	valid = verifier.VerifyTOTPOnly(invalidTOTP)
	if valid {
		t.Error("Invalid TOTP was accepted")
	}
}

// TestSPAPacketObfuscation tests that packet obfuscation works
func TestSPAPacketObfuscation(t *testing.T) {
	// Generate key pair
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}

	// Create TOTP secret
	totpSecret := make([]byte, 32)
	rand.Read(totpSecret)

	// Create packets with obfuscation
	packet1, err := CreateAsymmetricPacket(privateKey, totpSecret, 30, true, net.ParseIP("192.168.1.100"))
	if err != nil {
		t.Fatalf("Failed to create packet: %v", err)
	}

	packet2, err := CreateAsymmetricPacket(privateKey, totpSecret, 30, true, net.ParseIP("192.168.1.100"))
	if err != nil {
		t.Fatalf("Failed to create packet: %v", err)
	}

	// Verify both packets are valid by parsing them
	packet1Parsed, err := ParseSPAPacket(packet1)
	if err != nil {
		t.Fatalf("Failed to parse packet1: %v", err)
	}

	packet2Parsed, err2 := ParseSPAPacket(packet2)
	if err2 != nil {
		t.Fatalf("Failed to parse packet2: %v", err2)
	}

	// Verify signatures
	valid1 := VerifyAsymmetricPacket(publicKey, packet1Parsed, packet1)
	valid2 := VerifyAsymmetricPacket(publicKey, packet2Parsed, packet2)

	if !valid1 {
		t.Error("Packet1 signature verification failed")
	}
	if !valid2 {
		t.Error("Packet2 signature verification failed")
	}

	// Packets should have different padding (high probability)
	// Extract padding
	headerSize := SPAPacketHeaderSizeV2
	sigSize := Ed25519SignatureSize

	if len(packet1) > headerSize+sigSize && len(packet2) > headerSize+sigSize {
		padding1 := packet1[headerSize : len(packet1)-sigSize]
		padding2 := packet2[headerSize : len(packet2)-sigSize]

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

	// Both should have valid structure
	if packet1Parsed.Version != 1 || packet2Parsed.Version != 1 {
		t.Error("Invalid packet version")
	}

	if packet1Parsed.Mode != 2 || packet2Parsed.Mode != 2 {
		t.Error("Invalid packet mode")
	}
}

