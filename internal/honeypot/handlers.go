package honeypot

import (
	"fmt"
	"net"
	"strings"
	"time"

	"phantom-grid/internal/logger"
)

// handleSSH is implemented in ssh_handler.go
// This file now contains other service handlers

// handleHTTP is implemented in http_handler.go

// handleTelnet simulates Telnet login interaction
func (h *Handler) handleTelnet(conn net.Conn, remote, t string) {
	conn.Write([]byte("\r\nUbuntu 20.04.3 LTS\r\n\r\n"))
	time.Sleep(200 * time.Millisecond)
	conn.Write([]byte("server login: "))

	buf := make([]byte, 1024)
	loginAttempts := 0

	n, err := conn.Read(buf)
	if err != nil || n == 0 {
		return
	}
	username := strings.TrimSpace(string(buf[:n]))
	h.logChan <- fmt.Sprintf("[%s] TELNET LOGIN ATTEMPT: username='%s'", t, username)

	conn.Write([]byte("\r\nPassword: "))

	n, err = conn.Read(buf)
	if err != nil || n == 0 {
		return
	}
	password := strings.TrimSpace(string(buf[:n]))
	loginAttempts++

	ip := strings.Split(remote, ":")[0]
	h.logChan <- fmt.Sprintf("[%s] TELNET PASSWORD ATTEMPT #%d from %s (password length: %d)", t, loginAttempts, ip, len(password))
	logger.LogAttack(ip, fmt.Sprintf("TELNET_LOGIN: user=%s, pass=***", username))

	time.Sleep(500 * time.Millisecond)

	if loginAttempts < 3 {
		conn.Write([]byte("\r\nLogin incorrect\r\n\r\n"))
		conn.Write([]byte("server login: "))
		n, err = conn.Read(buf)
		if err != nil {
			return
		}
		username = strings.TrimSpace(string(buf[:n]))
		conn.Write([]byte("\r\nPassword: "))
		n, err = conn.Read(buf)
		if err != nil {
			return
		}
		loginAttempts++
		h.logChan <- fmt.Sprintf("[%s] TELNET PASSWORD ATTEMPT #%d from %s", t, loginAttempts, ip)
	}

	conn.Write([]byte("\r\nToo many login attempts. Connection closed.\r\n"))
}

// handleMySQL is implemented in mysql_handler.go

// handleRedis is implemented in redis_handler.go

// handleFTP simulates FTP server interaction
func (h *Handler) handleFTP(conn net.Conn, remote, t string) {
	ip := strings.Split(remote, ":")[0]
	h.logChan <- fmt.Sprintf("[%s] FTP connection from %s", t, ip)
	logger.LogAttack(ip, "FTP_CONNECTION")

	conn.Write([]byte("220 Welcome to FTP Server\r\n"))

	buf := make([]byte, 1024)
	authenticated := false

	for {
		n, err := conn.Read(buf)
		if err != nil || n == 0 {
			return
		}

		command := strings.TrimSpace(string(buf[:n]))
		h.logChan <- fmt.Sprintf("[%s] FTP COMMAND: %s", t, command)
		logger.LogAttack(ip, fmt.Sprintf("FTP: %s", command))

		parts := strings.Fields(command)
		if len(parts) == 0 {
			conn.Write([]byte("500 Syntax error\r\n"))
			continue
		}

		cmd := strings.ToUpper(parts[0])
		args := parts[1:]

		switch cmd {
		case "USER":
			if len(args) > 0 {
				username := args[0]
				h.logChan <- fmt.Sprintf("[%s] FTP USER: %s", t, username)
				conn.Write([]byte("331 Password required\r\n"))
			} else {
				conn.Write([]byte("501 Syntax error in parameters\r\n"))
			}
		case "PASS":
			if len(args) > 0 {
				password := args[0]
				h.logChan <- fmt.Sprintf("[%s] FTP PASS attempt (password length: %d)", t, len(password))
				logger.LogAttack(ip, "FTP_LOGIN: pass=***")
				time.Sleep(200 * time.Millisecond)
				conn.Write([]byte("530 Login incorrect\r\n"))
			} else {
				conn.Write([]byte("501 Syntax error in parameters\r\n"))
			}
		case "SYST":
			conn.Write([]byte("215 UNIX Type: L8\r\n"))
		case "PWD":
			conn.Write([]byte("257 \"/\" is current directory\r\n"))
		case "LIST", "LS":
			if authenticated {
				conn.Write([]byte("150 Opening ASCII mode data connection\r\n"))
				time.Sleep(100 * time.Millisecond)
				conn.Write([]byte("226 Transfer complete\r\n"))
			} else {
				conn.Write([]byte("530 Please login with USER and PASS\r\n"))
			}
		case "CWD":
			if len(args) > 0 {
				conn.Write([]byte(fmt.Sprintf("250 CWD command successful: %s\r\n", args[0])))
			} else {
				conn.Write([]byte("501 Syntax error in parameters\r\n"))
			}
		case "RETR", "GET":
			if len(args) > 0 {
				conn.Write([]byte("550 File not found\r\n"))
			} else {
				conn.Write([]byte("501 Syntax error in parameters\r\n"))
			}
		case "STOR", "PUT":
			if len(args) > 0 {
				conn.Write([]byte("553 Requested action not taken\r\n"))
			} else {
				conn.Write([]byte("501 Syntax error in parameters\r\n"))
			}
		case "QUIT", "BYE":
			conn.Write([]byte("221 Goodbye\r\n"))
			return
		case "HELP":
			conn.Write([]byte("214-The following commands are recognized:\r\n"))
			conn.Write([]byte(" USER PASS SYST PWD LIST CWD RETR STOR QUIT\r\n"))
			conn.Write([]byte("214 Help OK\r\n"))
		default:
			conn.Write([]byte("502 Command not implemented\r\n"))
		}
	}
}

