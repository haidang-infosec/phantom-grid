package honeypot

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"net"
	"strings"
	"time"

	"phantom-grid/internal/logger"
)

// handleSSH simulates professional SSH shell interaction
func (h *Handler) handleSSH(conn net.Conn, remote, t string) {
	time.Sleep(100 * time.Millisecond)

	ip := strings.Split(remote, ":")[0]
	vfs := NewVirtualFileSystem()
	currentDir := "/root"
	prompt := fmt.Sprintf("root@server:%s# ", currentDir)
	commandHistory := []string{}

	conn.Write([]byte(prompt))

	buf := make([]byte, 4096)
	for {
		// Set deadline to prevent Slowloris resource exhaustion
		conn.SetReadDeadline(time.Now().Add(30 * time.Second))
		conn.SetWriteDeadline(time.Now().Add(30 * time.Second))
		
		n, err := conn.Read(buf)
		if err != nil || n == 0 {
			return
		}

		input := strings.TrimSpace(string(buf[:n]))
		if len(input) == 0 {
			conn.Write([]byte(prompt))
			continue
		}

		// Log command
		h.logChan <- fmt.Sprintf("[%s] SSH COMMAND: %s", t, input)
		logger.LogAttack(ip, fmt.Sprintf("SSH: %s", input))
		commandHistory = append(commandHistory, input)

		parts := strings.Fields(input)
		if len(parts) == 0 {
			conn.Write([]byte(prompt))
			continue
		}

		cmd := parts[0]
		args := parts[1:]

		// Add small delay for realism
		randDelay, _ := rand.Int(rand.Reader, big.NewInt(100))
		time.Sleep(time.Duration(50+randDelay.Int64()) * time.Millisecond)

		switch cmd {
		case "exit", "logout", "quit":
			conn.Write([]byte("Connection closed by foreign host.\r\n"))
			return

		case "ls", "ls -la", "ls -l", "ls -a":
			output := vfs.ListFiles(currentDir)
			conn.Write([]byte(output + prompt))

		case "pwd":
			conn.Write([]byte(currentDir + "\r\n" + prompt))

		case "whoami":
			conn.Write([]byte("root\r\n" + prompt))

		case "id":
			conn.Write([]byte("uid=0(root) gid=0(root) groups=0(root)\r\n" + prompt))

		case "uname":
			if len(args) > 0 && args[0] == "-a" {
				conn.Write([]byte("Linux server 5.4.0-74-generic #83-Ubuntu SMP Sat May 8 02:35:04 UTC 2021 x86_64 x86_64 x86_64 GNU/Linux\r\n" + prompt))
			} else {
				conn.Write([]byte("Linux\r\n" + prompt))
			}

		case "cat", "less", "more":
			if len(args) > 0 {
				filename := args[0]
				if !strings.HasPrefix(filename, "/") {
					filename = currentDir + "/" + filename
				}
				if content, ok := vfs.ReadFile(filename); ok {
					conn.Write([]byte(content + prompt))
				} else if filename == "/etc/shadow" {
					conn.Write([]byte("cat: /etc/shadow: Permission denied\r\n" + prompt))
				} else {
					conn.Write([]byte(fmt.Sprintf("cat: %s: No such file or directory\r\n", args[0]) + prompt))
				}
			} else {
				conn.Write([]byte(fmt.Sprintf("%s: missing file operand\r\n", cmd) + prompt))
			}

		case "cd":
			if len(args) == 0 {
				currentDir = "/root"
			} else {
				dir := args[0]
				if dir == ".." {
					if currentDir != "/" {
						parts := strings.Split(strings.Trim(currentDir, "/"), "/")
						if len(parts) > 1 {
							currentDir = "/" + strings.Join(parts[:len(parts)-1], "/")
						} else {
							currentDir = "/"
						}
					}
				} else if dir == "/" {
					currentDir = "/"
				} else if strings.HasPrefix(dir, "/") {
					if vfs.FileExists(dir) {
						currentDir = dir
					} else {
						conn.Write([]byte(fmt.Sprintf("bash: cd: %s: No such file or directory\r\n", dir) + prompt))
						continue
					}
				} else {
					newDir := currentDir + "/" + dir
					if vfs.FileExists(newDir) {
						currentDir = newDir
					} else {
						conn.Write([]byte(fmt.Sprintf("bash: cd: %s: No such file or directory\r\n", dir) + prompt))
						continue
					}
				}
			}
			prompt = fmt.Sprintf("root@server:%s# ", currentDir)
			conn.Write([]byte(prompt))

		case "history":
			output := ""
			for i, cmd := range commandHistory {
				if i < len(commandHistory)-1 {
					output += fmt.Sprintf(" %4d  %s\r\n", i+1, cmd)
				}
			}
			conn.Write([]byte(output + prompt))

		case "ps":
			output := "  PID TTY          TIME CMD\r\n"
			output += "    1 ?        00:00:01 systemd\r\n"
			output += "  456 ?        00:00:02 sshd\r\n"
			output += "  789 ?        00:00:00 nginx\r\n"
			output += "  890 ?        00:00:01 mysqld\r\n"
			output += "  901 ?        00:00:00 redis-server\r\n"
			output += " 1234 ?        00:00:00 apache2\r\n"
			if len(args) > 0 && args[0] == "aux" {
				output = "USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND\r\n"
				output += "root         1  0.0  0.1  22536  3824 ?        Ss   Dec10   0:01 /sbin/init\r\n"
				output += "root       456  0.0  0.2  47864  8960 ?        Ss   Dec10   0:02 /usr/sbin/sshd\r\n"
				output += "root       789  0.0  0.1  23456  5120 ?        S    Dec10   0:00 /usr/sbin/nginx\r\n"
				output += "mysql      890  0.1  2.5 123456 25600 ?        Sl   Dec10   0:15 /usr/sbin/mysqld\r\n"
				output += "redis      901  0.0  0.3  12345  3072 ?        Ssl  Dec10   0:01 /usr/bin/redis-server\r\n"
				output += "www-data  1234  0.0  0.2  34567  2048 ?        S    Dec10   0:00 /usr/sbin/apache2\r\n"
			}
			conn.Write([]byte(output + prompt))

		case "netstat":
			output := "Active Internet connections (w/o servers)\r\n"
			output += "Proto Recv-Q Send-Q Local Address           Foreign Address         State\r\n"
			output += "tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN\r\n"
			output += "tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN\r\n"
			output += "tcp        0      0 0.0.0.0:443             0.0.0.0:*               LISTEN\r\n"
			output += "tcp        0      0 0.0.0.0:3306            0.0.0.0:*               LISTEN\r\n"
			if len(args) > 0 && args[0] == "-an" {
				output = "Active Internet connections (servers and established)\r\n"
				output += "Proto Recv-Q Send-Q Local Address           Foreign Address         State\r\n"
				output += "tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN\r\n"
				output += "tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN\r\n"
				output += "tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN\r\n"
			}
			conn.Write([]byte(output + prompt))

		case "ifconfig", "ip":
			if cmd == "ip" && len(args) > 0 && args[0] == "addr" {
				output := "1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000\r\n"
				output += "    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00\r\n"
				output += "    inet 127.0.0.1/8 scope host lo\r\n"
				output += "       valid_lft forever preferred_lft forever\r\n"
				output += "2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UP group default qlen 1000\r\n"
				output += "    link/ether 00:0c:29:12:34:56 brd ff:ff:ff:ff:ff:ff\r\n"
				output += "    inet 192.168.1.100/24 brd 192.168.1.255 scope global eth0\r\n"
				output += "       valid_lft forever preferred_lft forever\r\n"
				conn.Write([]byte(output + prompt))
			} else {
				output := "eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500\r\n"
				output += "        inet 192.168.1.100  netmask 255.255.255.0  broadcast 192.168.1.255\r\n"
				output += "        ether 00:0c:29:12:34:56  txqueuelen 1000  (Ethernet)\r\n"
				output += "        RX packets 12345  bytes 1234567 (1.2 MB)\r\n"
				output += "        RX errors 0  dropped 0  overruns 0  frame 0\r\n"
				output += "        TX packets 9876  bytes 987654 (987.6 KB)\r\n"
				output += "        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0\r\n"
				conn.Write([]byte(output + prompt))
			}

		case "df":
			output := "Filesystem     1K-blocks    Used Available Use% Mounted on\r\n"
			output += "/dev/sda1       20971520 8388608  12582912  40% /\r\n"
			output += "tmpfs             524288       0    524288   0% /dev/shm\r\n"
			output += "/dev/sda2       52428800 10485760  41943040  20% /home\r\n"
			conn.Write([]byte(output + prompt))

		case "free":
			output := "              total        used        free      shared  buff/cache   available\r\n"
			output += "Mem:         8192000     4096000     2048000      512000     2048000     3584000\r\n"
			output += "Swap:        2097152           0     2097152\r\n"
			conn.Write([]byte(output + prompt))

		case "top", "htop":
			output := "top - 10:30:15 up 5 days,  2:15,  1 user,  load average: 0.45, 0.52, 0.48\r\n"
			output += "Tasks: 125 total,   1 running, 124 sleeping,   0 stopped,   0 zombie\r\n"
			output += "%Cpu(s):  2.5 us,  1.2 sy,  0.0 ni, 96.3 id,  0.0 wa,  0.0 hi,  0.0 si,  0.0 st\r\n"
			output += "MiB Mem :   8000.0 total,   4000.0 free,   2000.0 used,   2000.0 buff/cache\r\n"
			output += "MiB Swap:   2048.0 total,   2048.0 free,      0.0 used.   5500.0 avail Mem\r\n"
			output += "\r\n"
			output += "  PID USER      PR  NI    VIRT    RES    SHR S  %CPU  %MEM     TIME+ COMMAND\r\n"
			output += "  890 mysql     20   0  123456  25600   5120 S   1.2   0.3   0:15.23 mysqld\r\n"
			output += "  456 root      20   0   47864   8960   2048 S   0.3   0.1   0:02.45 sshd\r\n"
			output += "    1 root      20   0   22536   3824   2048 S   0.0   0.0   0:01.23 systemd\r\n"
			conn.Write([]byte(output + prompt))

		case "grep":
			if len(args) > 0 {
				pattern := args[0]
				file := ""
				if len(args) > 1 {
					file = args[1]
				}
				if file != "" {
					if content, ok := vfs.ReadFile(file); ok {
						if strings.Contains(content, pattern) {
							conn.Write([]byte(fmt.Sprintf("%s: %s\r\n", file, pattern) + prompt))
						} else {
							conn.Write([]byte(prompt))
						}
					} else {
						conn.Write([]byte(fmt.Sprintf("grep: %s: No such file or directory\r\n", file) + prompt))
					}
				} else {
					conn.Write([]byte(fmt.Sprintf("grep: missing file operand\r\n") + prompt))
				}
			} else {
				conn.Write([]byte("grep: missing pattern\r\n" + prompt))
			}

		case "find":
			if len(args) > 0 {
				output := ""
				if args[0] == "/" || args[0] == "." {
					output = "/root/.bashrc\r\n/root/.bash_history\r\n/etc/passwd\r\n/etc/hosts\r\n"
				}
				conn.Write([]byte(output + prompt))
			} else {
				conn.Write([]byte("find: missing path\r\n" + prompt))
			}

		case "tail", "head":
			if len(args) > 0 {
				filename := args[0]
				if !strings.HasPrefix(filename, "/") {
					filename = currentDir + "/" + filename
				}
				if content, ok := vfs.ReadFile(filename); ok {
					lines := strings.Split(content, "\n")
					if cmd == "tail" {
						if len(lines) > 10 {
							lines = lines[len(lines)-10:]
						}
					} else {
						if len(lines) > 10 {
							lines = lines[:10]
						}
					}
					conn.Write([]byte(strings.Join(lines, "\n") + "\r\n" + prompt))
				} else {
					conn.Write([]byte(fmt.Sprintf("%s: %s: No such file or directory\r\n", cmd, args[0]) + prompt))
				}
			} else {
				conn.Write([]byte(fmt.Sprintf("%s: missing file operand\r\n", cmd) + prompt))
			}

		case "wget", "curl":
			if len(args) > 0 {
				url := args[0]
				conn.Write([]byte(fmt.Sprintf("--%s--  %s\r\n", time.Now().Format("2021-12-15 10:30:15"), url)))
				time.Sleep(300 * time.Millisecond)
				conn.Write([]byte("Connecting to " + strings.TrimPrefix(strings.TrimPrefix(url, "http://"), "https://") + "...\r\n"))
				time.Sleep(200 * time.Millisecond)
				conn.Write([]byte("HTTP request sent, awaiting response... 200 OK\r\n"))
				conn.Write([]byte("Length: 1024 (1.0K) [text/html]\r\n"))
				conn.Write([]byte("Saving to: 'index.html'\r\n"))
				time.Sleep(100 * time.Millisecond)
				conn.Write([]byte("100%[======================================>] 1,024      --.-K/s   in 0s\r\n"))
				conn.Write([]byte(fmt.Sprintf("'index.html' saved [1024/1024]\r\n" + prompt)))
			} else {
				conn.Write([]byte(fmt.Sprintf("%s: missing URL\r\n", cmd) + prompt))
			}

		case "systemctl", "service":
			if len(args) > 0 {
				action := args[0]
				service := ""
				if len(args) > 1 {
					service = args[1]
				}
				if action == "status" && service != "" {
					conn.Write([]byte(fmt.Sprintf("● %s.service - %s\r\n", service, strings.Title(service)+" Service")))
					conn.Write([]byte("   Loaded: loaded (/etc/systemd/system/" + service + ".service; enabled; vendor preset: enabled)\r\n"))
					conn.Write([]byte("   Active: active (running) since Wed 2021-12-15 10:00:00 UTC; 30min ago\r\n"))
					conn.Write([]byte(prompt))
				} else if action == "start" || action == "stop" || action == "restart" {
					conn.Write([]byte(fmt.Sprintf("Service %s %sed successfully\r\n", service, action) + prompt))
				} else {
					conn.Write([]byte(fmt.Sprintf("Unknown action: %s\r\n", action) + prompt))
				}
			} else {
				conn.Write([]byte(fmt.Sprintf("%s: missing argument\r\n", cmd) + prompt))
			}

		case "sudo":
			if len(args) > 0 {
				conn.Write([]byte(fmt.Sprintf("[sudo] password for root: ")))
				time.Sleep(500 * time.Millisecond)
				conn.Write([]byte("\r\n"))
				// Simulate command execution
				subCmd := strings.Join(args, " ")
				conn.Write([]byte(fmt.Sprintf("Executing: %s\r\n", subCmd) + prompt))
			} else {
				conn.Write([]byte("sudo: missing command\r\n" + prompt))
			}

		case "passwd":
			conn.Write([]byte("Changing password for root.\r\n"))
			conn.Write([]byte("Current password: "))
			time.Sleep(1000 * time.Millisecond)
			conn.Write([]byte("\r\n"))
			conn.Write([]byte("New password: "))
			time.Sleep(500 * time.Millisecond)
			conn.Write([]byte("\r\n"))
			conn.Write([]byte("Retype new password: "))
			time.Sleep(500 * time.Millisecond)
			conn.Write([]byte("\r\n"))
			conn.Write([]byte("passwd: password updated successfully\r\n" + prompt))

		case "su":
			if len(args) > 0 {
				conn.Write([]byte("Password: "))
				time.Sleep(500 * time.Millisecond)
				conn.Write([]byte("\r\n"))
				conn.Write([]byte("su: Authentication failure\r\n" + prompt))
			} else {
				conn.Write([]byte("su: must be run from a terminal\r\n" + prompt))
			}

		case "vi", "vim", "nano":
			if len(args) > 0 {
				conn.Write([]byte(fmt.Sprintf("Opening %s in %s...\r\n", args[0], cmd)))
				time.Sleep(200 * time.Millisecond)
				conn.Write([]byte("Press 'q' to quit\r\n"))
				// Wait for quit command
				time.Sleep(1000 * time.Millisecond)
				conn.Write([]byte(fmt.Sprintf("File saved: %s\r\n", args[0]) + prompt))
			} else {
				conn.Write([]byte(fmt.Sprintf("%s: missing file operand\r\n", cmd) + prompt))
			}

		case "mysql":
			conn.Write([]byte("Welcome to the MySQL monitor.  Commands end with ; or \\g.\r\n"))
			conn.Write([]byte("Your MySQL connection id is 12345\r\n"))
			conn.Write([]byte("Server version: 8.0.27 MySQL Community Server - GPL\r\n\r\n"))
			conn.Write([]byte("mysql> "))
			// Wait for command
			time.Sleep(2000 * time.Millisecond)
			conn.Write([]byte("\r\nERROR 1045 (28000): Access denied for user 'root'@'localhost' (using password: YES)\r\n" + prompt))

		case "python", "python3":
			if len(args) > 0 && args[0] == "-c" {
				conn.Write([]byte("Python 3.8.10 (default, Nov 26 2021, 20:14:08)\r\n"))
				conn.Write([]byte("[GCC 9.4.0] on linux\r\n"))
				conn.Write([]byte("Type \"help\", \"copyright\", \"credits\" or \"license\" for more information.\r\n"))
			} else {
				conn.Write([]byte("Python 3.8.10 (default, Nov 26 2021, 20:14:08)\r\n"))
				conn.Write([]byte("[GCC 9.4.0] on linux\r\n"))
				conn.Write([]byte("Type \"help\", \"copyright\", \"credits\" or \"license\" for more information.\r\n"))
				conn.Write([]byte(">>> "))
				time.Sleep(2000 * time.Millisecond)
				conn.Write([]byte("\r\n" + prompt))
			}

		case "clear", "reset":
			conn.Write([]byte("\033[2J\033[H" + prompt))

		default:
			time.Sleep(50 * time.Millisecond)
			conn.Write([]byte(fmt.Sprintf("bash: %s: command not found\r\n", cmd) + prompt))
		}
	}
}

