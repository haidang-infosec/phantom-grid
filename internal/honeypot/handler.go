package honeypot

import (
	"net"
)

// Handler handles different service interactions
type Handler struct {
	logChan chan<- string
}

// NewHandler creates a new handler instance
func NewHandler(logChan chan<- string) *Handler {
	return &Handler{
		logChan: logChan,
	}
}

// Handle routes connection to appropriate service handler
func (h *Handler) Handle(conn net.Conn, remote, serviceType, t string) {
	switch serviceType {
	case "ssh":
		h.handleSSH(conn, remote, t)
	case "http":
		h.handleHTTP(conn, remote, t)
	case "telnet":
		h.handleTelnet(conn, remote, t)
	case "mysql":
		h.handleMySQL(conn, remote, t)
	case "redis":
		h.handleRedis(conn, remote, t)
	case "ftp":
		h.handleFTP(conn, remote, t)
	default:
		h.handleSSH(conn, remote, t)
	}
}
