package honeypot

import (
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"phantom-grid/internal/config"
	"phantom-grid/internal/logger"
	"phantom-grid/internal/mirage"
)

// Honeypot manages multiple fake port listeners
type Honeypot struct {
	logChan   chan<- string
	listeners []net.Listener
	wg        sync.WaitGroup
}

// New creates a new Honeypot instance
func New(logChan chan<- string) *Honeypot {
	return &Honeypot{
		logChan:   logChan,
		listeners: make([]net.Listener, 0),
	}
}

// Start binds to fake ports and starts accepting connections
func (h *Honeypot) Start() error {
	var boundPorts []int

	// Try to bind all fake ports
	for _, port := range config.FakePorts {
		ln, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
		if err != nil {
			h.logChan <- fmt.Sprintf("[WARN] Cannot bind port %d: %v (XDP will redirect to 9999)", port, err)
			continue
		}
		h.listeners = append(h.listeners, ln)
		boundPorts = append(boundPorts, port)
		h.logChan <- fmt.Sprintf("[SYSTEM] Honeypot listening on port %d", port)

		h.wg.Add(1)
		go h.acceptLoop(ln, port)
	}

	// Bind fallback port
	if err := h.bindFallback(); err != nil {
		return err
	}

	h.logChan <- fmt.Sprintf("[SYSTEM] Honeypot bound to %d ports (%d direct, 1 fallback) - The Mirage active", len(h.listeners), len(boundPorts))
	h.logChan <- "[SYSTEM] Honeypot is now ACCEPTING connections on port 9999"
	h.logChan <- "[SYSTEM] Ready to receive traffic from external hosts"

	return nil
}

func (h *Honeypot) bindFallback() error {
	h.logChan <- fmt.Sprintf("[SYSTEM] Attempting to bind honeypot fallback port %d...", config.HoneypotPort)
	ln9999, err := net.Listen("tcp", fmt.Sprintf(":%d", config.HoneypotPort))
	if err != nil {
		h.logChan <- fmt.Sprintf("[ERROR] Cannot bind port %d: %v", config.HoneypotPort, err)
		h.logChan <- fmt.Sprintf("[ERROR] Port %d is REQUIRED for XDP redirect fallback!", config.HoneypotPort)
		h.logChan <- fmt.Sprintf("[ERROR] The eBPF program (internal/ebpf/programs/phantom.c) hardcodes redirect to port %d", config.HoneypotPort)
		h.logChan <- fmt.Sprintf("[ERROR] To free port %d, run: sudo lsof -i :%d && sudo kill -9 <PID>", config.HoneypotPort, config.HoneypotPort)
		h.logChan <- fmt.Sprintf("[ERROR] Or change HONEYPOT_PORT in internal/ebpf/programs/phantom.c and rebuild")
		h.logChan <- "[ERROR] FAILING FAST: Cannot use alternative ports due to eBPF hardcoded redirect"
		return fmt.Errorf("failed to bind honeypot fallback port %d (required for XDP redirect): %w", config.HoneypotPort, err)
	}

	h.listeners = append(h.listeners, ln9999)
	h.logChan <- fmt.Sprintf("[SYSTEM] Honeypot listening on port %d (fallback for redirected ports)", config.HoneypotPort)
	h.wg.Add(1)
	go h.acceptLoop(ln9999, config.HoneypotPort)
	return nil
}

func (h *Honeypot) acceptLoop(ln net.Listener, port int) {
	defer h.wg.Done()
	for {
		conn, err := ln.Accept()
		if err != nil {
			h.logChan <- fmt.Sprintf("[ERROR] Honeypot accept error on port %d: %v", port, err)
			continue
		}
		remoteAddr := conn.RemoteAddr()
		if remoteAddr != nil {
			h.logChan <- fmt.Sprintf("[DEBUG] Honeypot accepted connection on port %d from %s", port, remoteAddr.String())
		}
		go h.handleConnection(conn, port)
	}
}

func (h *Honeypot) handleConnection(conn net.Conn, originalPort int) {
	defer conn.Close()
	remoteAddr := conn.RemoteAddr()
	if remoteAddr == nil {
		return
	}

	remote := remoteAddr.String()
	ip := extractIP(remote)
	t := time.Now().Format("15:04:05")

	var serviceType string
	if originalPort == config.HoneypotPort {
		serviceType = mirage.SelectRandomService()
	} else {
		serviceType = mirage.SelectServiceByPort(originalPort)
	}
	banner := mirage.GetRandomBanner(serviceType)

	h.logChan <- fmt.Sprintf("[%s] TRAP HIT! IP: %s | Port: %d | Service: %s", t, ip, originalPort, strings.ToUpper(serviceType))
	logger.LogAttack(ip, fmt.Sprintf("TRAP_HIT_PORT_%d", originalPort))

	if _, err := conn.Write([]byte(banner)); err != nil {
		h.logChan <- fmt.Sprintf("[%s] Error sending banner to %s: %v", t, ip, err)
		return
	}

	handler := NewHandler(h.logChan)
	handler.Handle(conn, remote, serviceType, t)
}

func extractIP(remote string) string {
	if strings.HasPrefix(remote, "[") {
		endBracket := strings.Index(remote, "]")
		if endBracket > 0 {
			return remote[1:endBracket]
		}
		return strings.Split(remote, ":")[0]
	}
	return strings.Split(remote, ":")[0]
}

// Close stops all listeners
func (h *Honeypot) Close() error {
	for _, ln := range h.listeners {
		if err := ln.Close(); err != nil {
			return err
		}
	}
	h.wg.Wait()
	return nil
}

