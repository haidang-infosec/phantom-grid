package spa

import (
	"crypto/ed25519"
	"crypto/rand"
	"net"
	"testing"
	"time"

	"phantom-grid/internal/config"
)

func TestNewHandler(t *testing.T) {
	spaConfig := config.DefaultDynamicSPAConfig()
	verifier := NewVerifier(spaConfig)
	mapLoader := NewMapLoader(nil, nil, nil, nil, nil) // Mock map loader
	logChan := make(chan string, 10)

	handler := NewHandler(verifier, mapLoader, logChan, spaConfig, "")

	if handler == nil {
		t.Fatal("NewHandler returned nil")
	}

	if handler.verifier == nil {
		t.Fatal("Handler verifier is nil")
	}

	if handler.mapLoader == nil {
		t.Fatal("Handler mapLoader is nil")
	}
}

func TestIsStaticPacket(t *testing.T) {
	spaConfig := config.DefaultDynamicSPAConfig()
	verifier := NewVerifier(spaConfig)
	mapLoader := NewMapLoader(nil, nil, nil, nil, nil)
	logChan := make(chan string, 10)

	handler := NewHandler(verifier, mapLoader, logChan, spaConfig, "")

	// Test static token
	staticToken := []byte(config.SPASecretToken)
	if !handler.isStaticPacket(staticToken) {
		t.Error("Static token was not recognized")
	}

	// Test dynamic packet (starts with version byte 1)
	dynamicPacket := make([]byte, 100)
	dynamicPacket[0] = 1 // Version
	dynamicPacket[1] = 2 // Mode: Asymmetric
	if handler.isStaticPacket(dynamicPacket) {
		t.Error("Dynamic packet was recognized as static")
	}

	// Test wrong length
	wrongLength := make([]byte, 10)
	if handler.isStaticPacket(wrongLength) {
		t.Error("Wrong length packet was recognized as static")
	}
}

func TestProcessPacket_ValidAsymmetric(t *testing.T) {
	// Generate key pair
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}

	// Create TOTP secret
	totpSecret := make([]byte, 32)
	rand.Read(totpSecret)

	// Create valid packet
	packetData, err := CreateAsymmetricPacket(privateKey, totpSecret, 30, true)
	if err != nil {
		t.Fatalf("Failed to create packet: %v", err)
	}

	// Configure SPA
	spaConfig := config.DefaultDynamicSPAConfig()
	spaConfig.Mode = config.SPAModeAsymmetric
	spaConfig.PublicKey = publicKey
	spaConfig.TOTPSecret = totpSecret
	spaConfig.TOTPTimeStep = 30
	spaConfig.TOTPTolerance = 1

	// Create handler with mock map loader
	verifier := NewVerifier(spaConfig)
	mapLoader := NewMapLoader(nil, nil, nil, nil, nil) // Mock
	logChan := make(chan string, 10)

	handler := NewHandler(verifier, mapLoader, logChan, spaConfig, "")

	// Process packet
	clientIP := net.IPv4(192, 168, 1, 100)
	handler.processPacket(packetData, clientIP)

	// Check log messages
	select {
	case msg := <-logChan:
		if msg == "" {
			t.Error("Expected log message")
		}
	case <-time.After(1 * time.Second):
		t.Error("No log message received")
	}
}

func TestProcessPacket_InvalidPacket(t *testing.T) {
	spaConfig := config.DefaultDynamicSPAConfig()
	verifier := NewVerifier(spaConfig)
	mapLoader := NewMapLoader(nil, nil, nil, nil, nil)
	logChan := make(chan string, 10)

	handler := NewHandler(verifier, mapLoader, logChan, spaConfig, "")

	// Process invalid packet
	invalidPacket := make([]byte, 10)
	clientIP := net.IPv4(192, 168, 1, 100)

	handler.processPacket(invalidPacket, clientIP)

	// Should log error
	select {
	case msg := <-logChan:
		if msg == "" {
			t.Error("Expected error log message")
		}
	case <-time.After(1 * time.Second):
		t.Error("No error log message received")
	}
}

func TestProcessPacket_StaticPacket(t *testing.T) {
	spaConfig := config.DefaultDynamicSPAConfig()
	verifier := NewVerifier(spaConfig)
	mapLoader := NewMapLoader(nil, nil, nil, nil, nil)
	logChan := make(chan string, 10)

	handler := NewHandler(verifier, mapLoader, logChan, spaConfig, "")

	// Process static packet (should be ignored by handler)
	staticToken := []byte(config.SPASecretToken)
	clientIP := net.IPv4(192, 168, 1, 100)

	handler.processPacket(staticToken, clientIP)

	// Should not log anything (static packets handled by eBPF)
	select {
	case <-logChan:
		t.Error("Static packet should not be processed by handler")
	case <-time.After(100 * time.Millisecond):
		// Expected - no log message
	}
}

func TestHandler_StartStop(t *testing.T) {
	spaConfig := config.DefaultDynamicSPAConfig()
	verifier := NewVerifier(spaConfig)
	mapLoader := NewMapLoader(nil, nil, nil, nil, nil)
	logChan := make(chan string, 10)

	handler := NewHandler(verifier, mapLoader, logChan, spaConfig, "")

	// Start handler
	err := handler.Start()
	if err != nil {
		t.Fatalf("Failed to start handler: %v", err)
	}

	// Wait a bit for handler to start
	time.Sleep(100 * time.Millisecond)

	// Stop handler
	err = handler.Stop()
	if err != nil {
		t.Fatalf("Failed to stop handler: %v", err)
	}

	// Wait a bit for handler to stop
	time.Sleep(100 * time.Millisecond)
}

func TestProcessPacket_InvalidSignature(t *testing.T) {
	// Generate key pair
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}

	// Create TOTP secret
	totpSecret := make([]byte, 32)
	rand.Read(totpSecret)

	// Create valid packet
	packetData, err := CreateAsymmetricPacket(privateKey, totpSecret, 30, true)
	if err != nil {
		t.Fatalf("Failed to create packet: %v", err)
	}

	// Use wrong public key
	wrongPublicKey, _, _ := ed25519.GenerateKey(rand.Reader)

	// Configure SPA with wrong public key
	spaConfig := config.DefaultDynamicSPAConfig()
	spaConfig.Mode = config.SPAModeAsymmetric
	spaConfig.PublicKey = wrongPublicKey // Wrong key
	spaConfig.TOTPSecret = totpSecret
	spaConfig.TOTPTimeStep = 30
	spaConfig.TOTPTolerance = 1

	// Create handler
	verifier := NewVerifier(spaConfig)
	mapLoader := NewMapLoader(nil, nil, nil, nil, nil)
	logChan := make(chan string, 10)

	handler := NewHandler(verifier, mapLoader, logChan, spaConfig, "")

	// Process packet - should fail verification
	clientIP := net.IPv4(192, 168, 1, 100)
	handler.processPacket(packetData, clientIP)

	// Should log error
	select {
	case msg := <-logChan:
		if msg == "" {
			t.Error("Expected error log message for invalid signature")
		}
	case <-time.After(1 * time.Second):
		t.Error("No error log message received")
	}
}

