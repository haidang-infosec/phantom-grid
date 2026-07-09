package spa

import (
	"fmt"
	"net"
	"time"

	"phantom-grid/internal/config"
)

// Client represents an SPA client
type Client struct {
	ServerIP   string
	StaticToken string // Static token for legacy SPA mode
}

// NewClient creates a new SPA client
func NewClient(serverIP string) *Client {
	return &Client{
		ServerIP:   serverIP,
		StaticToken: config.SPASecretToken, // Default token
	}
}

// NewClientWithToken creates a new SPA client with custom static token
func NewClientWithToken(serverIP string, token string) *Client {
	if token == "" {
		token = config.SPASecretToken
	}
	return &Client{
		ServerIP:   serverIP,
		StaticToken: token,
	}
}

// SendMagicPacket sends the SPA Magic Packet to whitelist the client's IP
func (c *Client) SendMagicPacket() error {
	addr := net.JoinHostPort(c.ServerIP, fmt.Sprintf("%d", config.SPAMagicPort))
	conn, err := net.Dial("udp", addr)
	if err != nil {
		return fmt.Errorf("failed to create UDP connection: %w", err)
	}
	defer conn.Close()

	tokenBytes := []byte(c.StaticToken)
	_, err = conn.Write(tokenBytes)
	if err != nil {
		return fmt.Errorf("failed to send Magic Packet: %w", err)
	}

	time.Sleep(100 * time.Millisecond)
	return nil
}
