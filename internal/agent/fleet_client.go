package agent

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	"phantom-grid/internal/ebpf"
)

// FleetClient connects an Agent to the central Fleet Manager (Control Plane).
type FleetClient struct {
	fleetURL    string
	agentID     string
	phantomObjs *ebpf.PhantomObjects
	logChan     <-chan string
	httpClient  *http.Client
}

func NewFleetClient(fleetURL, agentID string, phantomObjs *ebpf.PhantomObjects, logChan <-chan string) *FleetClient {
	return &FleetClient{
		fleetURL:    fleetURL,
		agentID:     agentID,
		phantomObjs: phantomObjs,
		logChan:     logChan,
		httpClient:  &http.Client{Timeout: 5 * time.Second},
	}
}

func (fc *FleetClient) Start() {
	log.Printf("[FLEET] Connecting to Fleet Manager at %s as Agent: %s", fc.fleetURL, fc.agentID)
	
	// Start telemetry loop
	go fc.telemetryLoop()
	
	// Start log forwarding loop
	go fc.logLoop()
}

func (fc *FleetClient) telemetryLoop() {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		var dropped, authSuccess, authFailed uint64
		var key uint32 = 0

		if fc.phantomObjs != nil {
			fc.phantomObjs.StealthDrops.Lookup(&key, &dropped)
			fc.phantomObjs.SpaAuthSuccess.Lookup(&key, &authSuccess)
			fc.phantomObjs.SpaAuthFailed.Lookup(&key, &authFailed)
		}

		payload := map[string]interface{}{
			"agent_id":        fc.agentID,
			"dropped_packets": dropped,
			"auth_success":    authSuccess,
			"auth_failed":     authFailed,
		}

		data, _ := json.Marshal(payload)
		resp, err := fc.httpClient.Post(
			fmt.Sprintf("%s/api/fleet/telemetry", fc.fleetURL),
			"application/json",
			bytes.NewBuffer(data),
		)
		
		if err != nil {
			// Fail silently on periodic telemetry to avoid log spam
			continue
		}
		resp.Body.Close()
	}
}

func (fc *FleetClient) logLoop() {
	for msg := range fc.logChan {
		payload := map[string]string{
			"agent_id": fc.agentID,
			"message":  msg,
		}
		data, _ := json.Marshal(payload)
		
		resp, err := fc.httpClient.Post(
			fmt.Sprintf("%s/api/fleet/logs", fc.fleetURL),
			"application/json",
			bytes.NewBuffer(data),
		)
		
		if err == nil {
			resp.Body.Close()
		}
	}
}
