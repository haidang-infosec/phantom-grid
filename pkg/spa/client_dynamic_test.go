package spa

import (
	"crypto/ed25519"
	"crypto/rand"
	"net"
	"testing"
	"time"

	"phantom-grid/internal/config"
	"phantom-grid/internal/spa"
)

func TestNewDynamicClient_AsymmetricMode(t *testing.T) {
	// Generate key pair
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}

	// Create TOTP secret
	totpSecret := make([]byte, 32)
	rand.Read(totpSecret)

	// Configure SPA
	spaConfig := config.DefaultDynamicSPAConfig()
	spaConfig.Mode = config.SPAModeAsymmetric
	spaConfig.PrivateKey = privateKey
	spaConfig.TOTPSecret = totpSecret

	// Create client
	client, err := NewDynamicClient("127.0.0.1", spaConfig, net.ParseIP("192.168.1.100"))
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}

	if client == nil {
		t.Fatal("Client is nil")
	}

	if client.ServerIP != "127.0.0.1" {
		t.Errorf("Expected server IP 127.0.0.1, got %s", client.ServerIP)
	}

	if len(client.PrivateKey) == 0 {
		t.Error("Private key not set")
	}
}

func TestNewDynamicClient_DynamicMode(t *testing.T) {
	// Create secrets
	hmacSecret := make([]byte, 32)
	totpSecret := make([]byte, 32)
	rand.Read(hmacSecret)
	rand.Read(totpSecret)

	// Configure SPA
	spaConfig := config.DefaultDynamicSPAConfig()
	spaConfig.Mode = config.SPAModeDynamic
	spaConfig.HMACSecret = hmacSecret
	spaConfig.TOTPSecret = totpSecret

	// Create client
	client, err := NewDynamicClient("127.0.0.1", spaConfig, net.ParseIP("192.168.1.100"))
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}

	if client == nil {
		t.Fatal("Client is nil")
	}

	if len(client.HMACSecret) == 0 {
		t.Error("HMAC secret not set")
	}
}

func TestNewDynamicClient_MissingPrivateKey(t *testing.T) {
	// Configure SPA without private key
	spaConfig := config.DefaultDynamicSPAConfig()
	spaConfig.Mode = config.SPAModeAsymmetric
	spaConfig.PrivateKey = nil // Missing private key

	// Create client - should fail
	_, err := NewDynamicClient("127.0.0.1", spaConfig, net.ParseIP("192.168.1.100"))
	if err == nil {
		t.Error("Expected error for missing private key")
	}
}

func TestNewDynamicClient_MissingHMACSecret(t *testing.T) {
	// Configure SPA without HMAC secret
	spaConfig := config.DefaultDynamicSPAConfig()
	spaConfig.Mode = config.SPAModeDynamic
	spaConfig.HMACSecret = nil // Missing HMAC secret

	// Create client - should fail
	_, err := NewDynamicClient("127.0.0.1", spaConfig, net.ParseIP("192.168.1.100"))
	if err == nil {
		t.Error("Expected error for missing HMAC secret")
	}
}

func TestNewDynamicClient_UnsupportedMode(t *testing.T) {
	// Configure SPA with unsupported mode
	spaConfig := config.DefaultDynamicSPAConfig()
	spaConfig.Mode = config.SPAMode("unsupported")

	// Create client - should fail
	_, err := NewDynamicClient("127.0.0.1", spaConfig, net.ParseIP("192.168.1.100"))
	if err == nil {
		t.Error("Expected error for unsupported mode")
	}
}

func TestSendMagicPacket_AsymmetricMode(t *testing.T) {
	// Start a UDP server to receive the packet
	serverAddr, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to resolve address: %v", err)
	}

	serverConn, err := net.ListenUDP("udp", serverAddr)
	if err != nil {
		t.Fatalf("Failed to listen: %v", err)
	}
	defer serverConn.Close()

	// Get the actual port
	serverPort := serverConn.LocalAddr().(*net.UDPAddr).Port

	// Generate key pair
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}

	// Create TOTP secret
	totpSecret := make([]byte, 32)
	rand.Read(totpSecret)

	// Configure SPA
	spaConfig := config.DefaultDynamicSPAConfig()
	spaConfig.Mode = config.SPAModeAsymmetric
	spaConfig.PrivateKey = privateKey
	spaConfig.TOTPSecret = totpSecret

	// Create client with server port
	client, err := NewDynamicClient("127.0.0.1", spaConfig, net.ParseIP("192.168.1.100"))
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}

	// Override server port for testing
	originalPort := config.SPAMagicPort
	config.SPAMagicPort = serverPort
	defer func() { config.SPAMagicPort = originalPort }()

	// Send packet in goroutine
	done := make(chan error, 1)
	go func() {
		done <- client.SendMagicPacket()
	}()

	// Receive packet on server
	buffer := make([]byte, 1500)
	serverConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, _, err := serverConn.ReadFromUDP(buffer)
	if err != nil {
		t.Fatalf("Failed to receive packet: %v", err)
	}

	// Check packet was received
	if n == 0 {
		t.Error("No packet received")
	}

	// Wait for send to complete
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("SendMagicPacket failed: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Error("SendMagicPacket timed out")
	}

	// Verify packet structure
	packet, err := spa.ParseSPAPacket(buffer[:n])
	if err != nil {
		t.Fatalf("Failed to parse received packet: %v", err)
	}

	if packet.Version != 1 {
		t.Errorf("Expected version 1, got %d", packet.Version)
	}

	if packet.Mode != 2 {
		t.Errorf("Expected mode 2 (asymmetric), got %d", packet.Mode)
	}
}

func TestSendMagicPacket_DynamicMode(t *testing.T) {
	// Start a UDP server to receive the packet
	serverAddr, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to resolve address: %v", err)
	}

	serverConn, err := net.ListenUDP("udp", serverAddr)
	if err != nil {
		t.Fatalf("Failed to listen: %v", err)
	}
	defer serverConn.Close()

	// Create secrets
	hmacSecret := make([]byte, 32)
	totpSecret := make([]byte, 32)
	rand.Read(hmacSecret)
	rand.Read(totpSecret)

	// Configure SPA
	spaConfig := config.DefaultDynamicSPAConfig()
	spaConfig.Mode = config.SPAModeDynamic
	spaConfig.HMACSecret = hmacSecret
	spaConfig.TOTPSecret = totpSecret

	// Create client
	client, err := NewDynamicClient("127.0.0.1", spaConfig, net.ParseIP("192.168.1.100"))
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}

	// Override server port for testing
	serverPort := serverConn.LocalAddr().(*net.UDPAddr).Port
	originalPort := config.SPAMagicPort
	config.SPAMagicPort = serverPort
	defer func() { config.SPAMagicPort = originalPort }()

	// Send packet in goroutine
	done := make(chan error, 1)
	go func() {
		done <- client.SendMagicPacket()
	}()

	// Receive packet on server
	buffer := make([]byte, 1500)
	serverConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, _, err := serverConn.ReadFromUDP(buffer)
	if err != nil {
		t.Fatalf("Failed to receive packet: %v", err)
	}

	// Check packet was received
	if n == 0 {
		t.Error("No packet received")
	}

	// Wait for send to complete
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("SendMagicPacket failed: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Error("SendMagicPacket timed out")
	}

	// Verify packet structure
	packet, err := spa.ParseSPAPacket(buffer[:n])
	if err != nil {
		t.Fatalf("Failed to parse received packet: %v", err)
	}

	if packet.Version != 1 {
		t.Errorf("Expected version 1, got %d", packet.Version)
	}

	if packet.Mode != 1 {
		t.Errorf("Expected mode 1 (dynamic), got %d", packet.Mode)
	}
}

