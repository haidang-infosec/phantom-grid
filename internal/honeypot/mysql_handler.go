package honeypot

import (
	"fmt"
	"net"
	"strings"
	"time"

	"phantom-grid/internal/logger"
)

// handleMySQL simulates professional MySQL server interaction
func (h *Handler) handleMySQL(conn net.Conn, remote, t string) {
	ip := strings.Split(remote, ":")[0]
	h.logChan <- fmt.Sprintf("[%s] MySQL connection attempt from %s", t, ip)
	logger.LogAttack(ip, "MySQL_CONNECTION")

	// Send initial handshake packet
	handshake := []byte{
		0x4a, 0x00, 0x00, 0x00, // Packet length
		0x0a,                   // Protocol version (10)
	}
	handshake = append(handshake, []byte("8.0.27")...)
	handshake = append(handshake, 0x00)
	handshake = append(handshake, []byte{0x01, 0x00, 0x00, 0x00, 0x40, 0x41, 0x51, 0x27, 0x4a, 0x4b, 0x5c, 0x5d}...)
	handshake = append(handshake, []byte("mysql_native_password")...)
	handshake = append(handshake, 0x00)
	conn.Write(handshake)

	buf := make([]byte, 4096)
	authenticated := false
	username := ""

	for {
		// Set deadline to prevent Slowloris resource exhaustion
		conn.SetReadDeadline(time.Now().Add(30 * time.Second))
		conn.SetWriteDeadline(time.Now().Add(30 * time.Second))
		n, err := conn.Read(buf)
		if err != nil || n == 0 {
			return
		}

		// Parse login packet
		if !authenticated && n > 4 {
			usernameLen := int(buf[4])
			if usernameLen > 0 && usernameLen < 32 && n > 5+usernameLen {
				username = string(buf[5 : 5+usernameLen])
				h.logChan <- fmt.Sprintf("[%s] MySQL LOGIN: username='%s'", t, username)
				logger.LogAttack(ip, fmt.Sprintf("MySQL_LOGIN: user=%s", username))

				// Extract password if present
				passwordStart := 5 + usernameLen + 1
				if n > passwordStart {
					passwordLen := int(buf[passwordStart])
					if passwordLen > 0 && passwordLen < 255 && n > passwordStart+1 {
						password := string(buf[passwordStart+1 : passwordStart+1+passwordLen])
						h.logChan <- fmt.Sprintf("[%s] MySQL PASSWORD attempt (length: %d)", t, len(password))
						logger.LogAttack(ip, fmt.Sprintf("MySQL_PASSWORD: length=%d", len(password)))
					}
				}

				// Send error packet
				errorPacket := []byte{0xff, 0x15, 0x04, 0x23, 0x28, 0x30, 0x30, 0x30, 0x30, 0x34}
				errorPacket = append(errorPacket, []byte("Access denied for user '"+username+"'@'"+ip+"' (using password: YES)")...)
				errorPacket = append(errorPacket, 0x00)
				conn.Write(errorPacket)
				time.Sleep(200 * time.Millisecond)

				// Try to continue as if authenticated for command simulation
				authenticated = true
				conn.Write([]byte{0x07, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00}) // OK packet
				continue
			}
		}

		// Parse commands after authentication
		if authenticated && n > 4 {
			command := buf[4]
			commandStr := string(buf[5:n])

			h.logChan <- fmt.Sprintf("[%s] MySQL COMMAND: %s", t, commandStr)
			logger.LogAttack(ip, fmt.Sprintf("MySQL: %s", commandStr))

			switch command {
			case 0x03: // COM_QUERY
				query := strings.ToUpper(strings.TrimSpace(commandStr))
				response := h.handleMySQLQuery(query, ip, t)
				conn.Write(response)
			case 0x01: // COM_QUIT
				conn.Write([]byte{0x07, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00})
				return
			default:
				// Unknown command
				errorPacket := []byte{0xff, 0x15, 0x04, 0x23, 0x28, 0x30, 0x30, 0x30, 0x30, 0x34}
				errorPacket = append(errorPacket, []byte("Unknown command")...)
				errorPacket = append(errorPacket, 0x00)
				conn.Write(errorPacket)
			}
		}

		time.Sleep(100 * time.Millisecond)
	}
}

func (h *Handler) handleMySQLQuery(query string, ip, t string) []byte {
	query = strings.ToUpper(strings.TrimSpace(query))

	// SHOW DATABASES
	if strings.HasPrefix(query, "SHOW DATABASES") {
		databases := []string{"information_schema", "mysql", "performance_schema", "sys", "wordpress", "production", "test"}
		response := []byte{0x01, 0x00, 0x00, 0x01, 0x01} // Column count: 1
		response = append(response, []byte{0x27, 0x00, 0x00, 0x02, 0x03, 0x64, 0x65, 0x66}...) // Column definition
		response = append(response, []byte("Database")...)
		response = append(response, 0x00)
		for _, db := range databases {
			response = append(response, []byte(fmt.Sprintf("%c%s", len(db), db))...)
		}
		return response
	}

	// USE database
	if strings.HasPrefix(query, "USE ") {
		dbName := strings.TrimSpace(strings.TrimPrefix(query, "USE"))
		h.logChan <- fmt.Sprintf("[%s] MySQL USE DATABASE: %s", t, dbName)
		return []byte{0x07, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00} // OK packet
	}

	// SELECT queries
	if strings.HasPrefix(query, "SELECT") {
		if strings.Contains(query, "FROM USERS") || strings.Contains(query, "FROM USER") {
			// Simulate user table
			response := []byte{0x01, 0x00, 0x00, 0x01, 0x03} // 3 columns
			response = append(response, []byte("id")...)
			response = append(response, 0x00)
			response = append(response, []byte("username")...)
			response = append(response, 0x00)
			response = append(response, []byte("password")...)
			response = append(response, 0x00)
			// Add some fake rows
			response = append(response, []byte{0x01, 0x00, 0x00, 0x02, 0x31, 0x61, 0x64, 0x6d, 0x69, 0x6e, 0x2a, 0x2a, 0x2a}...)
			return response
		}
		if strings.Contains(query, "VERSION()") {
			return []byte{0x01, 0x00, 0x00, 0x01, 0x01, 0x07, 0x00, 0x00, 0x02, 0x38, 0x2e, 0x30, 0x2e, 0x32, 0x37} // "8.0.27"
		}
		// Generic SELECT response
		return []byte{0x01, 0x00, 0x00, 0x01, 0x00} // Empty result
	}

	// SHOW TABLES
	if strings.HasPrefix(query, "SHOW TABLES") {
		tables := []string{"users", "posts", "comments", "settings", "logs"}
		response := []byte{0x01, 0x00, 0x00, 0x01, 0x01} // Column count
		response = append(response, []byte("Tables_in_database")...)
		response = append(response, 0x00)
		for _, table := range tables {
			response = append(response, []byte(fmt.Sprintf("%c%s", len(table), table))...)
		}
		return response
	}

	// SHOW CREATE TABLE
	if strings.HasPrefix(query, "SHOW CREATE TABLE") {
		tableName := strings.TrimSpace(strings.TrimPrefix(query, "SHOW CREATE TABLE"))
		h.logChan <- fmt.Sprintf("[%s] MySQL SHOW CREATE TABLE: %s", t, tableName)
		response := []byte{0x01, 0x00, 0x00, 0x01, 0x02} // 2 columns
		response = append(response, []byte("Table")...)
		response = append(response, 0x00)
		response = append(response, []byte("Create Table")...)
		response = append(response, 0x00)
		createSQL := fmt.Sprintf("CREATE TABLE `%s` (`id` int(11) NOT NULL AUTO_INCREMENT, PRIMARY KEY (`id`))", tableName)
		response = append(response, []byte(fmt.Sprintf("%c%s", len(createSQL), createSQL))...)
		return response
	}

	// INSERT, UPDATE, DELETE
	if strings.HasPrefix(query, "INSERT") || strings.HasPrefix(query, "UPDATE") || strings.HasPrefix(query, "DELETE") {
		h.logChan <- fmt.Sprintf("[%s] MySQL MODIFY QUERY: %s", t, query)
		logger.LogAttack(ip, fmt.Sprintf("MySQL_MODIFY: %s", query))
		return []byte{0x07, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00} // OK - 1 row affected
	}

	// Default error response
	errorPacket := []byte{0xff, 0x15, 0x04, 0x23, 0x28, 0x30, 0x30, 0x30, 0x30, 0x34}
	errorPacket = append(errorPacket, []byte("You have an error in your SQL syntax")...)
	errorPacket = append(errorPacket, 0x00)
	return errorPacket
}

