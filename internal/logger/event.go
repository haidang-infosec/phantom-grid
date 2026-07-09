package logger

import (
	"time"
)

// EventType represents the type of security event
type EventType string

const (
	EventTypeTrapHit      EventType = "trap_hit"
	EventTypeCommand      EventType = "command"
	EventTypeSPAAuth      EventType = "spa_auth"
	EventTypeSPAFailed    EventType = "spa_failed"
	EventTypeStealthDrop  EventType = "stealth_drop"
	EventTypeOSMutation   EventType = "os_mutation"
	EventTypeEgressBlock  EventType = "egress_block"
	EventTypeConnection   EventType = "connection"
	EventTypeSystem      EventType = "system"
)

// SecurityEvent represents a structured security event for ELK export
type SecurityEvent struct {
	Timestamp   string                 `json:"@timestamp"`
	EventType   EventType              `json:"event_type"`
	SourceIP    string                 `json:"source_ip,omitempty"`
	DestinationIP string               `json:"destination_ip,omitempty"`
	Port        int                    `json:"port,omitempty"`
	Command     string                 `json:"command,omitempty"`
	Service     string                 `json:"service,omitempty"`
	Message     string                 `json:"message"`
	RiskLevel   string                 `json:"risk_level,omitempty"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
}

// NewSecurityEvent creates a new security event
func NewSecurityEvent(eventType EventType, message string) *SecurityEvent {
	return &SecurityEvent{
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		EventType: eventType,
		Message:   message,
		Metadata:   make(map[string]interface{}),
	}
}

// WithSourceIP sets the source IP
func (e *SecurityEvent) WithSourceIP(ip string) *SecurityEvent {
	e.SourceIP = ip
	return e
}

// WithDestinationIP sets the destination IP
func (e *SecurityEvent) WithDestinationIP(ip string) *SecurityEvent {
	e.DestinationIP = ip
	return e
}

// WithPort sets the port
func (e *SecurityEvent) WithPort(port int) *SecurityEvent {
	e.Port = port
	return e
}

// WithCommand sets the command
func (e *SecurityEvent) WithCommand(cmd string) *SecurityEvent {
	e.Command = cmd
	e.RiskLevel = "HIGH"
	return e
}

// WithService sets the service name
func (e *SecurityEvent) WithService(service string) *SecurityEvent {
	e.Service = service
	return e
}

// WithRiskLevel sets the risk level
func (e *SecurityEvent) WithRiskLevel(level string) *SecurityEvent {
	e.RiskLevel = level
	return e
}

// WithMetadata adds metadata
func (e *SecurityEvent) WithMetadata(key string, value interface{}) *SecurityEvent {
	if e.Metadata == nil {
		e.Metadata = make(map[string]interface{})
	}
	e.Metadata[key] = value
	return e
}

// ToMap converts SecurityEvent to map for ELK export
func (e *SecurityEvent) ToMap() map[string]interface{} {
	result := map[string]interface{}{
		"@timestamp": e.Timestamp,
		"event_type": string(e.EventType),
		"message":    e.Message,
	}

	if e.SourceIP != "" {
		result["source_ip"] = e.SourceIP
	}
	if e.DestinationIP != "" {
		result["destination_ip"] = e.DestinationIP
	}
	if e.Port > 0 {
		result["port"] = e.Port
	}
	if e.Command != "" {
		result["command"] = e.Command
	}
	if e.Service != "" {
		result["service"] = e.Service
	}
	if e.RiskLevel != "" {
		result["risk_level"] = e.RiskLevel
	}
	if len(e.Metadata) > 0 {
		result["metadata"] = e.Metadata
	}

	return result
}


