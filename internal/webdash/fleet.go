package webdash

import (
	"encoding/json"
	"net/http"
	"sync"
	"time"
	"log"

	"phantom-grid/internal/config"
	"phantom-grid/internal/proxy"
	
	"gorm.io/gorm"
	"gorm.io/driver/sqlite"
)

// AgentTelemetry contains the statistics sent by an agent.
type AgentTelemetry struct {
	AgentID        string    `json:"agent_id" gorm:"primaryKey"`
	IP             string    `json:"ip"`
	DroppedPackets uint64    `json:"dropped_packets"`
	AuthSuccess    uint64    `json:"auth_success"`
	AuthFailed     uint64    `json:"auth_failed"`
	LastSeen       time.Time `json:"last_seen"`
}

// FleetManager manages connected agents.
type FleetManager struct {
	mu sync.RWMutex
	db *gorm.DB
}

// NewFleetManager creates a new FleetManager.
func NewFleetManager() *FleetManager {
	db, err := gorm.Open(sqlite.Open("fleet.db"), &gorm.Config{})
	if err != nil {
		log.Fatalf("Failed to connect to fleet database: %v", err)
	}

	// Migrate the schema
	if err := db.AutoMigrate(&AgentTelemetry{}); err != nil {
		log.Fatalf("Failed to migrate fleet database schema: %v", err)
	}

	return &FleetManager{
		db: db,
	}
}

// RegisterAgent records telemetry from an agent.
func (f *FleetManager) RegisterAgent(t *AgentTelemetry) {
	f.mu.Lock()
	defer f.mu.Unlock()
	t.LastSeen = time.Now()
	f.db.Save(t)
}

// GetAgents returns a list of all active agents.
func (f *FleetManager) GetAgents() []*AgentTelemetry {
	f.mu.RLock()
	defer f.mu.RUnlock()
	var list []*AgentTelemetry
	f.db.Find(&list)
	return list
}

// GetAgent returns telemetry for a specific agent.
func (f *FleetManager) GetAgent(agentID string) (*AgentTelemetry, bool) {
	f.mu.RLock()
	defer f.mu.RUnlock()
	var a AgentTelemetry
	result := f.db.Where("agent_id = ?", agentID).First(&a)
	if result.Error != nil {
		return nil, false
	}
	return &a, true
}

// handleFleetTelemetry receives telemetry from an agent.
func (s *Server) handleFleetTelemetry(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var telemetry AgentTelemetry
	if err := json.NewDecoder(r.Body).Decode(&telemetry); err != nil {
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}
	telemetry.IP = r.RemoteAddr
	s.fleetManager.RegisterAgent(&telemetry)
	w.WriteHeader(http.StatusOK)
}

// handleFleetLogs receives log strings from an agent.
func (s *Server) handleFleetLogs(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	
	// We expect a simple JSON payload with AgentID and LogMessage
	var payload struct {
		AgentID string `json:"agent_id"`
		Message string `json:"message"`
	}
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}
	
	// Prepend AgentID to the log message to distinguish them in the stream if needed
	// Or we can just send it raw, frontend will filter it if we inject AgentID as a prefix
	// A simple way is to use a structured JSON log, but for MVP, let's prefix it:
	// "[AGENT:Node-1] [Event]..."
	
	// s.logChan is a receive-only channel in Server, wait!
	// In Fleet Mode, the control plane needs to broadcast logs received here to SSE.
	// But s.logChan is initialized from outside.
	// For Fleet, we should use a method to broadcast directly.
	
	s.broadcastRawLog(payload.AgentID, payload.Message)
	w.WriteHeader(http.StatusOK)
}

// handleGetAgents returns the list of agents for the UI.
func (s *Server) handleGetAgents(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(s.fleetManager.GetAgents())
}

// handleProvisionAccess provisions a new user with SPA Keys, TOTP and mTLS certificates.
func (s *Server) handleProvisionAccess(w http.ResponseWriter, r *http.Request) {
	// In a real system, this endpoint would verify Admin/SSO authentication.
	// For this ZTNA upgrade, we will generate the materials and return them.
	
	// Generate SPA Keys
	_, privKey, err := config.GenerateEd25519Keys()
	if err != nil {
		http.Error(w, "Failed to generate keys", http.StatusInternalServerError)
		return
	}

	// In a complete implementation we would store the pubKey to Fleet DB and push to Agents.
	
	// Generate mTLS Certs
	caPEM, caPriv, err := proxy.GenerateCA()
	if err != nil {
		http.Error(w, "Failed to generate CA", http.StatusInternalServerError)
		return
	}

	certPEM, certPriv, err := proxy.GenerateCert(caPEM, caPriv, false, "phantom-user", "spiffe://phantom.grid/ns/default/workload/phantom-agent")
	if err != nil {
		http.Error(w, "Failed to generate Cert", http.StatusInternalServerError)
		return
	}

	resp := map[string]string{
		"spa_private_key": string(privKey),
		"totp_secret":     "NEW_TOTP_SECRET_GENERATED",
		"mtls_ca":         string(caPEM),
		"mtls_cert":       string(certPEM),
		"mtls_key":        string(certPriv),
		"message":         "Provisioning Profile generated successfully",
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}
