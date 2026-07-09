package honeypot

import (
	"fmt"
	"net"
	"strings"
	"time"

	"phantom-grid/internal/logger"
)

// handleRedis simulates professional Redis server interaction
func (h *Handler) handleRedis(conn net.Conn, remote, t string) {
	ip := strings.Split(remote, ":")[0]
	h.logChan <- fmt.Sprintf("[%s] Redis connection from %s", t, ip)
	logger.LogAttack(ip, "REDIS_CONNECTION")

	buf := make([]byte, 4096)

	for {
		// Set deadline to prevent Slowloris resource exhaustion
		conn.SetReadDeadline(time.Now().Add(30 * time.Second))
		conn.SetWriteDeadline(time.Now().Add(30 * time.Second))
		n, err := conn.Read(buf)
		if err != nil || n == 0 {
			return
		}

		// Parse Redis protocol (RESP)
		command := strings.TrimSpace(string(buf[:n]))
		h.logChan <- fmt.Sprintf("[%s] REDIS COMMAND: %s", t, command)
		logger.LogAttack(ip, fmt.Sprintf("REDIS: %s", command))

		// Parse RESP format
		parts := h.parseRESP(command)
		if len(parts) == 0 {
			conn.Write([]byte("-ERR unknown command\r\n"))
			continue
		}

		cmd := strings.ToUpper(parts[0])
		args := parts[1:]

		time.Sleep(50 * time.Millisecond) // Realistic delay

		switch cmd {
		case "PING":
			conn.Write([]byte("+PONG\r\n"))

		case "INFO":
			info := "# Server\r\n"
			info += "redis_version:6.2.6\r\n"
			info += "redis_mode:standalone\r\n"
			info += "os:Linux 5.4.0 x86_64\r\n"
			info += "arch_bits:64\r\n"
			info += "multiplexing_api:epoll\r\n"
			info += "process_id:1234\r\n"
			info += "run_id:abc123def456\r\n"
			info += "tcp_port:6379\r\n"
			info += "uptime_in_seconds:86400\r\n"
			info += "uptime_in_days:1\r\n"
			info += "connected_clients:1\r\n"
			info += "used_memory:1048576\r\n"
			info += "used_memory_human:1.00M\r\n"
			conn.Write([]byte(fmt.Sprintf("$%d\r\n%s\r\n", len(info), info)))

		case "GET":
			if len(args) > 0 {
				key := args[0]
				h.logChan <- fmt.Sprintf("[%s] REDIS GET: key='%s'", t, key)
				// Return nil (key not found)
				conn.Write([]byte("$-1\r\n"))
			} else {
				conn.Write([]byte("-ERR wrong number of arguments for 'get' command\r\n"))
			}

		case "SET":
			if len(args) >= 2 {
				key := args[0]
				value := args[1]
				h.logChan <- fmt.Sprintf("[%s] REDIS SET: key='%s', value_length=%d", t, key, len(value))
				logger.LogAttack(ip, fmt.Sprintf("REDIS_SET: key=%s, value_len=%d", key, len(value)))
				_ = value // Logged above
				conn.Write([]byte("+OK\r\n"))
			} else {
				conn.Write([]byte("-ERR wrong number of arguments for 'set' command\r\n"))
			}

		case "KEYS":
			pattern := "*"
			if len(args) > 0 {
				pattern = args[0]
			}
			h.logChan <- fmt.Sprintf("[%s] REDIS KEYS: pattern='%s'", t, pattern)
			// Return empty list
			conn.Write([]byte("*0\r\n"))

		case "AUTH":
			if len(args) > 0 {
				password := args[0]
				h.logChan <- fmt.Sprintf("[%s] REDIS AUTH attempt (password length: %d)", t, len(password))
				logger.LogAttack(ip, "REDIS_AUTH: password=***")
				conn.Write([]byte("-ERR invalid password\r\n"))
			} else {
				conn.Write([]byte("-ERR wrong number of arguments for 'auth' command\r\n"))
			}

		case "CONFIG":
			if len(args) > 0 && strings.ToUpper(args[0]) == "GET" {
				configKey := "*"
				if len(args) > 1 {
					configKey = args[1]
				}
				h.logChan <- fmt.Sprintf("[%s] REDIS CONFIG GET: %s", t, configKey)
				logger.LogAttack(ip, fmt.Sprintf("REDIS_CONFIG: %s", configKey))
				conn.Write([]byte("*2\r\n$7\r\nrequirepass\r\n$0\r\n\r\n"))
			} else {
				conn.Write([]byte("-ERR unknown subcommand or wrong number of arguments\r\n"))
			}

		case "HGET":
			if len(args) >= 2 {
				key := args[0]
				field := args[1]
				h.logChan <- fmt.Sprintf("[%s] REDIS HGET: key='%s', field='%s'", t, key, field)
				conn.Write([]byte("$-1\r\n"))
			} else {
				conn.Write([]byte("-ERR wrong number of arguments for 'hget' command\r\n"))
			}

		case "HSET":
			if len(args) >= 3 {
				key := args[0]
				field := args[1]
				value := args[2]
				h.logChan <- fmt.Sprintf("[%s] REDIS HSET: key='%s', field='%s', value_length=%d", t, key, field, len(value))
				logger.LogAttack(ip, fmt.Sprintf("REDIS_HSET: key=%s, field=%s, value_len=%d", key, field, len(value)))
				_ = value // Logged above
				conn.Write([]byte(":1\r\n"))
			} else {
				conn.Write([]byte("-ERR wrong number of arguments for 'hset' command\r\n"))
			}

		case "HGETALL":
			if len(args) > 0 {
				key := args[0]
				h.logChan <- fmt.Sprintf("[%s] REDIS HGETALL: key='%s'", t, key)
				conn.Write([]byte("*0\r\n"))
			} else {
				conn.Write([]byte("-ERR wrong number of arguments for 'hgetall' command\r\n"))
			}

		case "LPUSH", "RPUSH":
			if len(args) >= 2 {
				key := args[0]
				_ = args[1] // value
				h.logChan <- fmt.Sprintf("[%s] REDIS %s: key='%s'", t, cmd, key)
				logger.LogAttack(ip, fmt.Sprintf("REDIS_%s: key=%s", cmd, key))
				conn.Write([]byte(":1\r\n"))
			} else {
				conn.Write([]byte(fmt.Sprintf("-ERR wrong number of arguments for '%s' command\r\n", strings.ToLower(cmd))))
			}

		case "LRANGE":
			if len(args) >= 3 {
				key := args[0]
				start := args[1]
				stop := args[2]
				h.logChan <- fmt.Sprintf("[%s] REDIS LRANGE: key='%s', start=%s, stop=%s", t, key, start, stop)
				conn.Write([]byte("*0\r\n"))
			} else {
				conn.Write([]byte("-ERR wrong number of arguments for 'lrange' command\r\n"))
			}

		case "FLUSHALL", "FLUSHDB":
			h.logChan <- fmt.Sprintf("[%s] REDIS %s: DANGEROUS COMMAND!", t, cmd)
			logger.LogAttack(ip, fmt.Sprintf("REDIS_%s: DANGEROUS", cmd))
			conn.Write([]byte("+OK\r\n"))

		case "EVAL", "EVALSHA":
			if len(args) > 0 {
				script := args[0]
				h.logChan <- fmt.Sprintf("[%s] REDIS %s: script execution attempt (length: %d)", t, cmd, len(script))
				logger.LogAttack(ip, fmt.Sprintf("REDIS_%s: script_length=%d", cmd, len(script)))
				conn.Write([]byte("-ERR script execution not allowed\r\n"))
			} else {
				conn.Write([]byte("-ERR wrong number of arguments\r\n"))
			}

		case "SAVE", "BGSAVE":
			h.logChan <- fmt.Sprintf("[%s] REDIS %s: backup command", t, cmd)
			conn.Write([]byte("+OK\r\n"))

		case "DBSIZE":
			conn.Write([]byte(":0\r\n"))

		case "SELECT":
			if len(args) > 0 {
				db := args[0]
				h.logChan <- fmt.Sprintf("[%s] REDIS SELECT: database=%s", t, db)
				conn.Write([]byte("+OK\r\n"))
			} else {
				conn.Write([]byte("-ERR wrong number of arguments for 'select' command\r\n"))
			}

		case "QUIT", "EXIT":
			conn.Write([]byte("+OK\r\n"))
			return

		default:
			conn.Write([]byte(fmt.Sprintf("-ERR unknown command '%s'\r\n", strings.ToLower(cmd))))
		}
	}
}

// parseRESP parses Redis RESP protocol format
func (h *Handler) parseRESP(input string) []string {
	parts := []string{}
	lines := strings.Split(input, "\r\n")
	
	for i := 0; i < len(lines); i++ {
		line := lines[i]
		if len(line) == 0 {
			continue
		}
		
		if line[0] == '*' {
			// Array
			count := 0
			fmt.Sscanf(line, "*%d", &count)
			for j := 0; j < count && i+1 < len(lines); j++ {
				i++
				if i < len(lines) && len(lines[i]) > 0 && lines[i][0] == '$' {
					// String length
					var strLen int
					fmt.Sscanf(lines[i], "$%d", &strLen)
					i++
					if i < len(lines) {
						parts = append(parts, lines[i])
					}
				}
			}
		} else if line[0] == '$' {
			// String
			var strLen int
			fmt.Sscanf(line, "$%d", &strLen)
			i++
			if i < len(lines) {
				parts = append(parts, lines[i])
			}
		} else {
			// Simple string or error
			if strings.HasPrefix(line, "+") || strings.HasPrefix(line, "-") {
				parts = append(parts, line[1:])
			} else {
				// Try to parse as space-separated command
				fields := strings.Fields(line)
				parts = append(parts, fields...)
			}
		}
	}
	
	// Fallback: simple space-separated parsing
	if len(parts) == 0 {
		parts = strings.Fields(input)
	}
	
	return parts
}

