package spa

import (
	"crypto/ed25519"
	"fmt"
	"net"
	"time"

	"phantom-grid/internal/config"
	"phantom-grid/internal/spa"
)

// DynamicClient represents a dynamic SPA client with Ed25519/HMAC support
type DynamicClient struct {
	ServerIP        string
	PrivateKey      ed25519.PrivateKey // For asymmetric mode
	HMACSecret      []byte             // For dynamic mode
	TOTPSecret      []byte             // Shared TOTP secret
	SPAConfig       *config.DynamicSPAConfig
	ClientIP        net.IP             // IP to bind to the packet
}

// NewDynamicClient creates a new dynamic SPA client
func NewDynamicClient(serverIP string, spaConfig *config.DynamicSPAConfig, clientIP net.IP) (*DynamicClient, error) {
	client := &DynamicClient{
		ServerIP:  serverIP,
		SPAConfig: spaConfig,
		ClientIP:  clientIP,
	}

	// Set secrets based on mode
	switch spaConfig.Mode {
	case config.SPAModeAsymmetric:
		if len(spaConfig.PrivateKey) == 0 {
			return nil, fmt.Errorf("private key required for asymmetric mode")
		}
		client.PrivateKey = spaConfig.PrivateKey
		client.TOTPSecret = spaConfig.TOTPSecret

	case config.SPAModeDynamic:
		if len(spaConfig.HMACSecret) == 0 {
			return nil, fmt.Errorf("HMAC secret required for dynamic mode")
		}
		client.HMACSecret = spaConfig.HMACSecret
		client.TOTPSecret = spaConfig.TOTPSecret

	default:
		return nil, fmt.Errorf("unsupported SPA mode: %s", spaConfig.Mode)
	}

	return client, nil
}

// SendMagicPacket sends a dynamic SPA packet
func (c *DynamicClient) SendMagicPacket() error {
	addr := net.JoinHostPort(c.ServerIP, fmt.Sprintf("%d", config.SPAMagicPort))
	conn, err := net.Dial("udp", addr)
	if err != nil {
		return fmt.Errorf("failed to create UDP connection: %w", err)
	}
	defer conn.Close()

	var packetData []byte
	var createErr error
	switch c.SPAConfig.Mode {
	case config.SPAModeAsymmetric:
		packetData, createErr = spa.CreateAsymmetricPacket(
			c.PrivateKey,
			c.TOTPSecret,
			c.SPAConfig.TOTPTimeStep,
			c.SPAConfig.EnableObfuscation,
			c.ClientIP,
		)
		if createErr != nil {
			return fmt.Errorf("failed to create asymmetric packet: %w", createErr)
		}

	case config.SPAModeDynamic:
		packetData, createErr = spa.CreateDynamicPacket(
			c.HMACSecret,
			c.TOTPSecret,
			c.SPAConfig.TOTPTimeStep,
			c.SPAConfig.EnableObfuscation,
			c.ClientIP,
		)
		if createErr != nil {
			return fmt.Errorf("failed to create dynamic packet: %w", createErr)
		}

	default:
		return fmt.Errorf("unsupported SPA mode: %s", c.SPAConfig.Mode)
	}

	_, err = conn.Write(packetData)
	if err != nil {
		return fmt.Errorf("failed to send Magic Packet: %w", err)
	}

	time.Sleep(100 * time.Millisecond)
	return nil
}

