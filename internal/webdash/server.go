package webdash

import (
	"embed"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"

	"phantom-grid/internal/ebpf"
)

//go:embed ui/*
var uiFS embed.FS

// Server manages the web dashboard
type Server struct {
	port         int
	logChan      <-chan string
	phantomObjs     *ebpf.PhantomObjects
	egressObjs      *ebpf.EgressObjects
	clients         map[chan string]bool
	addClient       chan chan string
	removeClient    chan chan string
	externalLogChan chan string
	authManager     *AuthManager
	fleetManager    *FleetManager
}

// NewServer creates a new web dashboard server
func NewServer(port int, logChan <-chan string, phantomObjs *ebpf.PhantomObjects, egressObjs *ebpf.EgressObjects) *Server {
	return &Server{
		port:         port,
		logChan:      logChan,
		phantomObjs:  phantomObjs,
		egressObjs:      egressObjs,
		clients:         make(map[chan string]bool),
		addClient:       make(chan chan string),
		removeClient:    make(chan chan string),
		externalLogChan: make(chan string, 100),
		authManager:     NewAuthManager("users.json"),
		fleetManager:    NewFleetManager(),
	}
}

// Start runs the web server and the log broadcaster
func (s *Server) Start() {
	go s.broadcastLogs()

	// Setup routes
	mux := http.NewServeMux()

	// Auth APIs
	mux.HandleFunc("/api/auth/login", s.handleLogin)
	mux.HandleFunc("/api/auth/logout", s.handleLogout)
	mux.HandleFunc("/api/auth/password", s.handlePassword)
	mux.HandleFunc("/api/auth/me", s.handleMe)

	// API Routes
	mux.HandleFunc("/api/logs", s.handleLogs)
	mux.HandleFunc("/api/stats", s.handleStats)
	mux.HandleFunc("/api/settings", s.handleSettings)
	
	// Prometheus metrics
	mux.HandleFunc("/metrics", s.handleMetrics)

	// Fleet APIs
	mux.HandleFunc("/api/fleet/telemetry", s.handleFleetTelemetry)
	mux.HandleFunc("/api/fleet/logs", s.handleFleetLogs)
	mux.HandleFunc("/api/fleet/agents", s.handleGetAgents)

	// Serve static files from embedded FS
	fs := http.FileServer(http.FS(uiFS))
	mux.Handle("/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/login" {
			r.URL.Path = "/ui/login.html"
		} else if r.URL.Path == "/" || r.URL.Path == "/index.html" {
			r.URL.Path = "/ui/index.html"
		} else {
			r.URL.Path = "/ui" + r.URL.Path
		}
		fs.ServeHTTP(w, r)
	}))

	// Wrap the entire mux with AuthMiddleware
	protectedMux := s.authManager.AuthMiddleware(mux)

	addr := fmt.Sprintf(":%d", s.port)
	log.Printf("[SYSTEM] Web Dashboard starting on http://localhost%s", addr)
	
	go func() {
		if err := http.ListenAndServe(addr, protectedMux); err != nil {
			log.Printf("[!] Web Dashboard server error: %v", err)
		}
	}()
}

// broadcastLogs reads from logChan and broadcasts to all connected SSE clients
func (s *Server) broadcastLogs() {
	for {
		select {
		case client := <-s.addClient:
			s.clients[client] = true
		case client := <-s.removeClient:
			delete(s.clients, client)
		case msg, ok := <-s.logChan:
			if ok {
				s.sendToClients(msg)
			}
		case msg := <-s.externalLogChan:
			s.sendToClients(msg)
		}
	}
}

func (s *Server) sendToClients(msg string) {
	for client := range s.clients {
		select {
		case client <- msg:
		default:
			// If client buffer is full, drop message
		}
	}
}

func (s *Server) broadcastRawLog(agentID, msg string) {
	// Prepend AgentID to message
	s.externalLogChan <- "[AGENT:" + agentID + "] " + msg
}

// handleLogs handles SSE connections for log streaming
func (s *Server) handleLogs(w http.ResponseWriter, r *http.Request) {
	// Set headers for SSE
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	clientChan := make(chan string, 100)
	s.addClient <- clientChan

	defer func() {
		s.removeClient <- clientChan
		close(clientChan)
	}()

	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "Streaming unsupported", http.StatusInternalServerError)
		return
	}

	for {
		select {
		case msg := <-clientChan:
			// SSE format requires "data: <message>\n\n"
			// Replace newlines in message so it doesn't break SSE framing
			safeMsg := strings.ReplaceAll(msg, "\n", " ")
			fmt.Fprintf(w, "data: %s\n\n", safeMsg)
			flusher.Flush()
		case <-r.Context().Done():
			return // Client disconnected
		}
	}
}

// handleStats returns eBPF statistics as JSON
func (s *Server) handleStats(w http.ResponseWriter, r *http.Request) {
	agentID := r.URL.Query().Get("agent")
	if agentID != "" {
		// Fleet mode: return stats for requested agent
		if agent, ok := s.fleetManager.GetAgent(agentID); ok {
			json.NewEncoder(w).Encode(map[string]uint64{
				"dropped_packets": agent.DroppedPackets,
				"auth_success":    agent.AuthSuccess,
				"auth_failed":     agent.AuthFailed,
			})
			return
		}
	}

	stats := map[string]uint64{
		"dropped_packets": 0,
		"auth_success":    0,
		"auth_failed":     0,
	}

	if s.phantomObjs != nil {
		// Read stats from eBPF maps
		var dropped, authSuccess, authFailed uint64
		var key uint32 = 0

		if err := s.phantomObjs.StealthDrops.Lookup(&key, &dropped); err == nil {
			stats["dropped_packets"] = dropped
		}
		if err := s.phantomObjs.SpaAuthSuccess.Lookup(&key, &authSuccess); err == nil {
			stats["auth_success"] = authSuccess
		}
		if err := s.phantomObjs.SpaAuthFailed.Lookup(&key, &authFailed); err == nil {
			stats["auth_failed"] = authFailed
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(stats)
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}

	token, err := s.authManager.Authenticate(req.Username, req.Password)
	if err != nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "phantom_session",
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		MaxAge:   86400, // 24 hours
	})

	w.WriteHeader(http.StatusOK)
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("phantom_session")
	if err == nil {
		s.authManager.Logout(cookie.Value)
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "phantom_session",
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		MaxAge:   -1,
	})

	w.WriteHeader(http.StatusOK)
}

func (s *Server) handlePassword(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	user, ok := r.Context().Value(UserContextKey).(User)
	if !ok {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	var req struct {
		OldPassword string `json:"old_password"`
		NewPassword string `json:"new_password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}

	if err := s.authManager.ChangePassword(user.Username, req.OldPassword, req.NewPassword); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	w.WriteHeader(http.StatusOK)
}

func (s *Server) handleMe(w http.ResponseWriter, r *http.Request) {
	user, ok := r.Context().Value(UserContextKey).(User)
	if !ok {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"username": user.Username,
		"role":     user.Role,
	})
}

func (s *Server) handleSettings(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		settings := LoadSettings()
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(settings)
		return
	}

	if r.Method == http.MethodPost {
		user, ok := r.Context().Value(UserContextKey).(User)
		if !ok || user.Role != RoleAdmin {
			http.Error(w, "Forbidden: Admin only", http.StatusForbidden)
			return
		}

		var settings Settings
		if err := json.NewDecoder(r.Body).Decode(&settings); err != nil {
			http.Error(w, "Bad request", http.StatusBadRequest)
			return
		}

		if err := SaveSettings(&settings); err != nil {
			http.Error(w, "Failed to save settings", http.StatusInternalServerError)
			return
		}

		w.WriteHeader(http.StatusOK)
		return
	}

	http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
}

func (s *Server) handleMetrics(w http.ResponseWriter, r *http.Request) {
	var dropped, authSuccess, authFailed uint64
	var key uint32 = 0

	// Aggregate from local eBPF or Fleet Manager
	if s.phantomObjs != nil {
		s.phantomObjs.StealthDrops.Lookup(&key, &dropped)
		s.phantomObjs.SpaAuthSuccess.Lookup(&key, &authSuccess)
		s.phantomObjs.SpaAuthFailed.Lookup(&key, &authFailed)
	} else {
		for _, a := range s.fleetManager.GetAgents() {
			dropped += a.DroppedPackets
			authSuccess += a.AuthSuccess
			authFailed += a.AuthFailed
		}
	}

	w.Header().Set("Content-Type", "text/plain; version=0.0.4")
	
	fmt.Fprintf(w, "# HELP phantom_dropped_packets_total Total number of packets dropped by XDP\n")
	fmt.Fprintf(w, "# TYPE phantom_dropped_packets_total counter\n")
	fmt.Fprintf(w, "phantom_dropped_packets_total %d\n", dropped)
	
	fmt.Fprintf(w, "# HELP phantom_spa_auth_success_total Successful SPA authorizations\n")
	fmt.Fprintf(w, "# TYPE phantom_spa_auth_success_total counter\n")
	fmt.Fprintf(w, "phantom_spa_auth_success_total %d\n", authSuccess)
	
	fmt.Fprintf(w, "# HELP phantom_spa_auth_failed_total Failed SPA authorizations\n")
	fmt.Fprintf(w, "# TYPE phantom_spa_auth_failed_total counter\n")
	fmt.Fprintf(w, "phantom_spa_auth_failed_total %d\n", authFailed)
}
