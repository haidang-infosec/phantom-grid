package honeypot

import (
	"fmt"
	"net"
	"strings"
	"time"

	"phantom-grid/internal/logger"
)

// handleHTTP simulates professional HTTP server interaction
func (h *Handler) handleHTTP(conn net.Conn, remote, t string) {
	buf := make([]byte, 8192)
	// Set deadline to prevent Slowloris resource exhaustion
	conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
	n, err := conn.Read(buf)
	if err != nil {
		return
	}

	request := string(buf[:n])
	ip := strings.Split(remote, ":")[0]

	lines := strings.Split(request, "\r\n")
	if len(lines) == 0 {
		return
	}

	requestLine := lines[0]
	h.logChan <- fmt.Sprintf("[%s] HTTP REQUEST: %s", t, requestLine)
	logger.LogAttack(ip, fmt.Sprintf("HTTP: %s", requestLine))

	parts := strings.Fields(requestLine)
	if len(parts) < 2 {
		return
	}

	method := parts[0]
	path := parts[1]
	path = strings.Split(path, "?")[0] // Remove query string

	// Extract User-Agent
	userAgent := "Unknown"
	for _, line := range lines {
		if strings.HasPrefix(strings.ToLower(line), "user-agent:") {
			userAgent = strings.TrimSpace(strings.TrimPrefix(line, "User-Agent:"))
			break
		}
	}

	// Extract credentials from POST
	if method == "POST" {
		bodyStart := strings.Index(request, "\r\n\r\n")
		if bodyStart > 0 {
			body := request[bodyStart+4:]
			if strings.Contains(body, "password") || strings.Contains(body, "pass") {
				h.logChan <- fmt.Sprintf("[%s] HTTP POST with credentials detected! User-Agent: %s", t, userAgent)
				logger.LogAttack(ip, fmt.Sprintf("HTTP_POST_CREDENTIALS: %s", body))
			}
		}
	}

	var response string
	time.Sleep(time.Duration(50+len(path)*2) * time.Millisecond) // Realistic delay

	switch path {
	case "/", "/index.html", "/index.php":
		response = "HTTP/1.1 200 OK\r\n"
		response += "Server: nginx/1.18.0 (Ubuntu)\r\n"
		response += "Content-Type: text/html; charset=UTF-8\r\n"
		response += "Connection: keep-alive\r\n"
		response += "X-Powered-By: PHP/7.4.3\r\n"
		response += "\r\n"
		response += `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Welcome - Server Management</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; background: #f5f5f5; }
        .container { background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        h1 { color: #333; }
        .nav { margin: 20px 0; }
        .nav a { margin-right: 15px; color: #0066cc; text-decoration: none; }
        .nav a:hover { text-decoration: underline; }
    </style>
</head>
<body>
    <div class="container">
        <h1>Welcome to Server Management Portal</h1>
        <p>System is running normally. All services are operational.</p>
        <div class="nav">
            <a href="/admin">Admin Panel</a>
            <a href="/login">Login</a>
            <a href="/dashboard">Dashboard</a>
            <a href="/api">API</a>
        </div>
        <p>Server Time: ` + time.Now().Format("2006-01-02 15:04:05") + `</p>
    </div>
</body>
</html>`

	case "/admin", "/admin.php", "/admin.html", "/administrator", "/wp-admin":
		response = "HTTP/1.1 200 OK\r\n"
		response += "Server: nginx/1.18.0 (Ubuntu)\r\n"
		response += "Content-Type: text/html; charset=UTF-8\r\n"
		response += "Set-Cookie: session_id=abc123xyz; Path=/; HttpOnly\r\n"
		response += "\r\n"
		response += `<!DOCTYPE html>
<html>
<head>
    <title>Administration Panel</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; background: #2c3e50; color: white; }
        .login-box { background: #34495e; padding: 30px; border-radius: 8px; max-width: 400px; margin: 100px auto; }
        input { width: 100%; padding: 10px; margin: 10px 0; border: none; border-radius: 4px; }
        button { width: 100%; padding: 12px; background: #3498db; color: white; border: none; border-radius: 4px; cursor: pointer; }
        button:hover { background: #2980b9; }
    </style>
</head>
<body>
    <div class="login-box">
        <h2>Administration Panel</h2>
        <form method="POST" action="/admin/login">
            <input type="text" name="username" placeholder="Username" required>
            <input type="password" name="password" placeholder="Password" required>
            <button type="submit">Login</button>
        </form>
        <p style="font-size: 12px; color: #95a5a6;">Forgot password? <a href="/admin/reset" style="color: #3498db;">Reset here</a></p>
    </div>
</body>
</html>`

	case "/login", "/login.php", "/signin":
		response = "HTTP/1.1 200 OK\r\n"
		response += "Server: Apache/2.4.41 (Debian)\r\n"
		response += "Content-Type: text/html; charset=UTF-8\r\n"
		response += "\r\n"
		response += `<!DOCTYPE html>
<html>
<head>
    <title>User Login</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; background: #ecf0f1; }
        .form-container { background: white; padding: 30px; border-radius: 8px; max-width: 350px; margin: 50px auto; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        input { width: 100%; padding: 10px; margin: 10px 0; border: 1px solid #ddd; border-radius: 4px; box-sizing: border-box; }
        button { width: 100%; padding: 12px; background: #27ae60; color: white; border: none; border-radius: 4px; cursor: pointer; }
    </style>
</head>
<body>
    <div class="form-container">
        <h2>User Login</h2>
        <form method="POST" action="/login/check">
            <input type="text" name="user" placeholder="Username" required>
            <input type="password" name="pass" placeholder="Password" required>
            <button type="submit">Sign In</button>
        </form>
    </div>
</body>
</html>`

	case "/api", "/api/v1", "/api/v1/users", "/api/users":
		response = "HTTP/1.1 200 OK\r\n"
		response += "Content-Type: application/json\r\n"
		response += "Access-Control-Allow-Origin: *\r\n"
		response += "\r\n"
		response += `{"status":"ok","data":[{"id":1,"username":"admin","email":"admin@server.com","role":"administrator"},{"id":2,"username":"user","email":"user@server.com","role":"user"}],"timestamp":"` + time.Now().Format(time.RFC3339) + `"}`

	case "/api/v1/config", "/api/config":
		response = "HTTP/1.1 200 OK\r\n"
		response += "Content-Type: application/json\r\n"
		response += "\r\n"
		response += `{"database":{"host":"localhost","port":3306,"name":"production"},"api_key":"sk_live_51H3ll0W0rld","version":"1.2.3"}`

	case "/robots.txt":
		response = "HTTP/1.1 200 OK\r\n"
		response += "Content-Type: text/plain\r\n"
		response += "\r\n"
		response += "User-agent: *\nDisallow: /admin/\nDisallow: /private/\nDisallow: /config/\nAllow: /public/"

	case "/.git/config", "/.git/HEAD", "/.git":
		response = "HTTP/1.1 403 Forbidden\r\n"
		response += "Server: nginx/1.18.0 (Ubuntu)\r\n"
		response += "Content-Type: text/html\r\n"
		response += "\r\n"
		response += "<h1>403 Forbidden</h1><p>You don't have permission to access this resource.</p>"

	case "/phpinfo.php", "/info.php":
		response = "HTTP/1.1 200 OK\r\n"
		response += "Server: Apache/2.4.41 (Debian)\r\n"
		response += "Content-Type: text/html\r\n"
		response += "\r\n"
		response += `<html><head><title>phpinfo()</title></head><body>
<h1>PHP Version 7.4.3</h1>
<p>System: Linux server 5.4.0-74-generic</p>
<p>Server API: Apache 2.0 Handler</p>
<p>Document Root: /var/www/html</p>
</body></html>`

	case "/wp-login.php", "/wordpress/wp-admin":
		response = "HTTP/1.1 200 OK\r\n"
		response += "Server: nginx/1.18.0 (Ubuntu)\r\n"
		response += "Content-Type: text/html; charset=UTF-8\r\n"
		response += "\r\n"
		response += `<!DOCTYPE html>
<html>
<head>
    <title>WordPress Login</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; background: #f0f0f1; }
        .login { background: white; padding: 30px; border-radius: 4px; max-width: 320px; margin: 50px auto; }
        input { width: 100%; padding: 10px; margin: 10px 0; border: 1px solid #ddd; }
        button { width: 100%; padding: 12px; background: #0073aa; color: white; border: none; }
    </style>
</head>
<body>
    <div class="login">
        <h1>WordPress</h1>
        <form method="POST">
            <input type="text" name="log" placeholder="Username or Email">
            <input type="password" name="pwd" placeholder="Password">
            <button type="submit">Log In</button>
        </form>
    </div>
</body>
</html>`

	case "/dashboard", "/panel":
		response = "HTTP/1.1 302 Found\r\n"
		response += "Location: /login\r\n"
		response += "\r\n"

	default:
		if method == "POST" {
			h.logChan <- fmt.Sprintf("[%s] HTTP POST to %s - credentials may be present", t, path)
			response = "HTTP/1.1 302 Found\r\n"
			response += "Location: /admin/dashboard\r\n"
			response += "Set-Cookie: auth_token=invalid; Path=/\r\n"
			response += "\r\n"
		} else if strings.Contains(path, ".php") || strings.Contains(path, ".jsp") || strings.Contains(path, ".asp") {
			response = "HTTP/1.1 200 OK\r\n"
			response += "Server: Apache/2.4.41 (Debian)\r\n"
			response += "Content-Type: text/html\r\n"
			response += "\r\n"
			response += "<html><body><h1>Page Not Found</h1><p>The requested page could not be found.</p></body></html>"
		} else {
			response = "HTTP/1.1 404 Not Found\r\n"
			response += "Server: nginx/1.18.0 (Ubuntu)\r\n"
			response += "Content-Type: text/html; charset=UTF-8\r\n"
			response += "\r\n"
			response += `<!DOCTYPE html>
<html>
<head>
    <title>404 Not Found</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; text-align: center; }
        h1 { color: #e74c3c; }
    </style>
</head>
<body>
    <h1>404 Not Found</h1>
    <p>The requested URL ` + path + ` was not found on this server.</p>
    <p><a href="/">Return to homepage</a></p>
</body>
</html>`
		}
	}

	conn.Write([]byte(response))
	time.Sleep(100 * time.Millisecond)
}

