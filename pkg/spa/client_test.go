package spa

import (
	"fmt"
	"net"
	"testing"
	"time"

	"phantom-grid/internal/config"
)

func TestNewClientSetsServerIP(t *testing.T) {
	ip := "127.0.0.1"
	c := NewClient(ip)
	if c == nil {
		t.Fatalf("expected non-nil client")
	}
	if c.ServerIP != ip {
		t.Fatalf("expected ServerIP %q, got %q", ip, c.ServerIP)
	}
}

func TestSendMagicPacketSendsCorrectToken(t *testing.T) {
	// Start a local UDP listener on the SPA magic port to capture the packet.
	addrStr := net.JoinHostPort("127.0.0.1", fmt.Sprintf("%d", config.SPAMagicPort))
	udpAddr, err := net.ResolveUDPAddr("udp", addrStr)
	if err != nil {
		t.Fatalf("failed to resolve UDP addr: %v", err)
	}

	conn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		t.Fatalf("failed to listen on UDP: %v", err)
	}
	defer conn.Close()

	receivedCh := make(chan []byte, 1)

	go func() {
		buf := make([]byte, 1024)
		_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		n, _, err := conn.ReadFromUDP(buf)
		if err != nil {
			return
		}
		receivedCh <- buf[:n]
	}()

	client := NewClient("127.0.0.1")
	if err := client.SendMagicPacket(); err != nil {
		t.Fatalf("SendMagicPacket returned error: %v", err)
	}

	select {
	case data := <-receivedCh:
		if len(data) != config.SPATokenLen {
			t.Fatalf("expected token length %d, got %d", config.SPATokenLen, len(data))
		}
		if string(data) != config.SPASecretToken {
			t.Fatalf("unexpected token data: got %q, want %q", string(data), config.SPASecretToken)
		}
	case <-time.After(3 * time.Second):
		t.Fatalf("timed out waiting for SPA packet")
	}
}


