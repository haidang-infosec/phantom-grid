package spa

import (
	"crypto/subtle"
	"encoding/binary"
	"fmt"
	"net"
	"time"

	"phantom-grid/internal/config"
)

// Handler handles dynamic SPA packet verification in user-space
type Handler struct {
	verifier    *Verifier
	mapLoader   *MapLoader
	logChan     chan<- string
	spaConfig   *config.DynamicSPAConfig
	staticToken string // Static token for legacy SPA mode (configurable)
	udpConn     *net.UDPConn
	stopChan    chan struct{}
}

// NewHandler creates a new SPA packet handler
func NewHandler(verifier *Verifier, mapLoader *MapLoader, logChan chan<- string, spaConfig *config.DynamicSPAConfig, staticToken string) *Handler {
	// Use default token if not provided
	if staticToken == "" {
		staticToken = config.SPASecretToken
	}
	return &Handler{
		verifier:   verifier,
		mapLoader:  mapLoader,
		logChan:    logChan,
		spaConfig:  spaConfig,
		staticToken: staticToken,
		stopChan:   make(chan struct{}),
	}
}

// Start starts the UDP listener for SPA packets
func (h *Handler) Start() error {
	addr := &net.UDPAddr{
		IP:   net.IPv4zero,
		Port: int(config.SPAMagicPort),
	}

	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return fmt.Errorf("failed to listen on SPA port: %w", err)
	}

	h.udpConn = conn

	// Start packet handler goroutine
	go h.handlePackets()

	// Log startup information (use fmt.Printf for immediate output)
	msg := fmt.Sprintf("[SPA] User-space handler started on port %d", config.SPAMagicPort)
	fmt.Printf("%s\n", msg)
	select {
	case h.logChan <- msg:
	default:
	}
	
	if h.spaConfig != nil {
		msg := fmt.Sprintf("[SPA] Mode: %s", h.spaConfig.Mode)
		fmt.Printf("%s\n", msg)
		select {
		case h.logChan <- msg:
		default:
		}
	} else {
		msg := fmt.Sprintf("[SPA] Mode: static (legacy)")
		fmt.Printf("%s\n", msg)
		select {
		case h.logChan <- msg:
		default:
		}
	}
	if h.staticToken != "" {
		msg := fmt.Sprintf("[SPA] Static token configured (length: %d)", len(h.staticToken))
		fmt.Printf("%s\n", msg)
		select {
		case h.logChan <- msg:
		default:
		}
	}
	readyMsg := fmt.Sprintf("[SPA] Handler ready to receive packets")
	fmt.Printf("%s\n", readyMsg)
	// Non-blocking send to log channel
	select {
	case h.logChan <- readyMsg:
		default:
		// Channel full, but we already printed to stdout
	}

	return nil
}

// Stop stops the handler
func (h *Handler) Stop() error {
	close(h.stopChan)
	if h.udpConn != nil {
		return h.udpConn.Close()
	}
	return nil
}

// handlePackets processes incoming SPA packets
func (h *Handler) handlePackets() {
	buffer := make([]byte, 1500) // Max UDP packet size
	msg := fmt.Sprintf("[SPA] Packet handler goroutine started, listening for packets...")
	fmt.Printf("%s\n", msg)
	// Non-blocking send to log channel
	select {
	case h.logChan <- msg:
	default:
		// Channel full, but we already printed to stdout
	}

	for {
		select {
		case <-h.stopChan:
			msg := fmt.Sprintf("[SPA] Packet handler stopping...")
			fmt.Printf("%s\n", msg)
			select {
			case h.logChan <- msg:
			default:
			}
			return
		default:
			// Set read deadline to allow checking stopChan
			h.udpConn.SetReadDeadline(time.Now().Add(1 * time.Second))
			
			n, clientAddr, err := h.udpConn.ReadFromUDP(buffer)
			if err != nil {
				if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
					// Timeout is expected, continue loop
					continue
				}
				errMsg := fmt.Sprintf("[SPA] Read error: %v", err)
				fmt.Printf("%s\n", errMsg)
				select {
				case h.logChan <- errMsg:
				default:
				}
				continue
			}

			// Log that we received a packet (both to log channel and stdout for debugging)
			msg := fmt.Sprintf("[SPA] Received packet from %s (length: %d bytes)", clientAddr.IP, n)
			fmt.Printf("%s\n", msg)
			// Non-blocking send to log channel
			select {
			case h.logChan <- msg:
			default:
				// Channel full, but we already printed to stdout
			}

			// Process packet
			go h.processPacket(buffer[:n], clientAddr.IP)
		}
	}
}

// processPacket verifies and processes a single SPA packet
func (h *Handler) processPacket(packetData []byte, clientIP net.IP) {
	// Check if packet is static or dynamic
	if h.isStaticPacket(packetData) {
		// Static packets are handled by eBPF, do nothing in user space
		return
	}
	
	// If not static packet and not dynamic packet, log for debugging
	if len(packetData) > 0 {
		debugLen := 8
		if len(packetData) < debugLen {
			debugLen = len(packetData)
		}
		msg := fmt.Sprintf("[SPA] Received non-matching packet from %s (length: %d, first bytes: %x, expected token length: %d)", clientIP, len(packetData), packetData[:debugLen], len(h.staticToken))
		fmt.Printf("%s\n", msg)
		select {
		case h.logChan <- msg:
		default:
		}
	}

	// Parse dynamic packet
	packet, err := ParseSPAPacket(packetData)
	if err != nil {
		errMsg := fmt.Sprintf("[SPA] Failed to parse packet from %s: %v", clientIP, err)
		fmt.Printf("%s\n", errMsg)
		select {
		case h.logChan <- errMsg:
		default:
		}
		return
	}

	// Verify packet
	valid, err := h.verifier.VerifyPacket(packetData, clientIP)
	if !valid {
		errMsg := fmt.Sprintf("[SPA] Invalid packet from %s: %v", clientIP, err)
		fmt.Printf("%s\n", errMsg)
		select {
		case h.logChan <- errMsg:
		default:
		}
		return
	}

	// Whitelist IP
	if err := h.mapLoader.WhitelistIP(clientIP, h.spaConfig.ReplayWindowSeconds); err != nil {
		errMsg := fmt.Sprintf("[SPA] Failed to whitelist IP %s: %v", clientIP, err)
		fmt.Printf("%s\n", errMsg)
		select {
		case h.logChan <- errMsg:
		default:
		}
		return
	}

	successMsg := fmt.Sprintf("[SPA] Successfully authenticated and whitelisted IP: %s", clientIP)
	fmt.Printf("%s\n", successMsg)
	select {
	case h.logChan <- successMsg:
	default:
	}
	
	totpMsg := fmt.Sprintf("[SPA] TOTP: %d, Timestamp: %d", packet.TOTP, packet.Timestamp)
	fmt.Printf("%s\n", totpMsg)
	select {
	case h.logChan <- totpMsg:
	default:
	}
}

// isStaticPacket checks if packet is legacy static token
func (h *Handler) isStaticPacket(data []byte) bool {
	// Static token is ASCII string, dynamic packet starts with version byte (1 or 2)
	staticTokenBytes := []byte(h.staticToken)
	
	// Check length first
	if len(data) != len(staticTokenBytes) {
		return false
	}
	
	// Check if it's a dynamic packet (starts with version byte 1 or 2)
	if len(data) > 0 && (data[0] == 1 || data[0] == 2) {
		return false
	}
	
	// Use constant time comparison to prevent timing attacks
	return subtle.ConstantTimeCompare(data, staticTokenBytes) == 1
}

// GetClientIPFromPacket extracts client IP from packet (for logging)
func GetClientIPFromPacket(packetData []byte) (net.IP, error) {
	// This is a helper function - in practice, IP comes from UDP connection
	// This is just for demonstration
	if len(packetData) < 14 {
		return nil, fmt.Errorf("packet too short")
	}
	
	// Extract timestamp to verify packet structure
	timestamp := int64(binary.BigEndian.Uint64(packetData[2:10]))
	_ = timestamp // Use timestamp for validation
	
	return nil, fmt.Errorf("IP must come from UDP connection")
}

