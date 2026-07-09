package webdash

import (
	"encoding/json"
	"net/http"
	"sync"
	"time"
)

// AgentTelemetry contains the statistics sent by an agent.
type AgentTelemetry struct {
	AgentID        string `json:"agent_id"`
	IP             string `json:"ip"`
	DroppedPackets uint64 `json:"dropped_packets"`
	AuthSuccess    uint64 `json:"auth_success"`
	AuthFailed     uint64 `json:"auth_failed"`
	LastSeen       time.Time `json:"last_seen"`
}

// FleetManager manages connected agents.
type FleetManager struct {
	mu     sync.RWMutex
	agents map[string]*AgentTelemetry
}

// NewFleetManager creates a new FleetManager.
func NewFleetManager() *FleetManager {
	return &FleetManager{
		agents: make(map[string]*AgentTelemetry),
	}
}

// RegisterAgent records telemetry from an agent.
func (f *FleetManager) RegisterAgent(t *AgentTelemetry) {
	f.mu.Lock()
	defer f.mu.Unlock()
	t.LastSeen = time.Now()
	f.agents[t.AgentID] = t
}

// GetAgents returns a list of all active agents.
func (f *FleetManager) GetAgents() []*AgentTelemetry {
	f.mu.RLock()
	defer f.mu.RUnlock()
	var list []*AgentTelemetry
	for _, a := range f.agents {
		list = append(list, a)
	}
	return list
}

// GetAgent returns telemetry for a specific agent.
func (f *FleetManager) GetAgent(agentID string) (*AgentTelemetry, bool) {
	f.mu.RLock()
	defer f.mu.RUnlock()
	a, ok := f.agents[agentID]
	return a, ok
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
