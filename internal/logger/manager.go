package logger

import (
	"fmt"
	"log"
	"strings"

	"phantom-grid/internal/config"
	"phantom-grid/internal/exporter"
)

// Manager manages log output to dashboard and/or ELK
type Manager struct {
	outputMode   config.OutputMode
	logChan      chan string
	elkExporter  *exporter.ELKExporter
	dashboardChan chan<- string
}

// NewManager creates a new logger manager
func NewManager(outputMode config.OutputMode, elkConfig config.ELKConfiguration, dashboardChan chan<- string) (*Manager, error) {
	mgr := &Manager{
		outputMode:    outputMode,
		logChan:       make(chan string, 1000),
		dashboardChan: dashboardChan,
	}

	// Initialize ELK exporter if needed
	if outputMode == config.OutputModeELK || outputMode == config.OutputModeBoth {
		elkConfig.Enabled = true
		exporter, err := exporter.NewELKExporter(elkConfig)
		if err != nil {
			return nil, fmt.Errorf("failed to initialize ELK exporter: %w", err)
		}
		mgr.elkExporter = exporter
		log.Printf("[SYSTEM] ELK exporter initialized: %s", strings.Join(elkConfig.Addresses, ", "))
	}

	// Start log processing goroutine
	go mgr.processLogs()

	return mgr, nil
}

// LogChannel returns the channel for sending log messages
func (m *Manager) LogChannel() chan<- string {
	return m.logChan
}

// processLogs processes logs and routes them to dashboard and/or ELK
func (m *Manager) processLogs() {
	for msg := range m.logChan {
		// Route to dashboard if enabled
		if m.outputMode == config.OutputModeDashboard || m.outputMode == config.OutputModeBoth {
			if m.dashboardChan != nil {
				select {
				case m.dashboardChan <- msg:
				default:
					// Channel full, skip (non-blocking)
				}
			}
		}

		// Route to ELK if enabled
		if (m.outputMode == config.OutputModeELK || m.outputMode == config.OutputModeBoth) && m.elkExporter != nil {
			event := m.parseLogMessage(msg)
			if event != nil {
				if err := m.elkExporter.Export(event.ToMap()); err != nil {
					log.Printf("[ELK] Failed to export event: %v", err)
				}
			}
		}
	}
}

// parseLogMessage parses a log message and creates a SecurityEvent
func (m *Manager) parseLogMessage(msg string) *SecurityEvent {
	// Parse different log message formats
	if strings.Contains(msg, "TRAP HIT") {
		// Extract IP and port from message
		event := NewSecurityEvent(EventTypeTrapHit, msg)
		event.RiskLevel = "HIGH"
		return event
	}

	if strings.Contains(msg, "COMMAND") {
		// Extract command from message
		event := NewSecurityEvent(EventTypeCommand, msg)
		event.RiskLevel = "HIGH"
		// Try to extract command
		if idx := strings.Index(msg, "COMMAND:"); idx != -1 {
			cmd := strings.TrimSpace(msg[idx+8:])
			event.Command = cmd
		}
		return event
	}

	if strings.Contains(msg, "[SPA] Successful authentication") {
		event := NewSecurityEvent(EventTypeSPAAuth, msg)
		event.RiskLevel = "INFO"
		return event
	}

	if strings.Contains(msg, "[SPA] Failed authentication") {
		event := NewSecurityEvent(EventTypeSPAFailed, msg)
		event.RiskLevel = "MEDIUM"
		return event
	}

	if strings.Contains(msg, "stealth") || strings.Contains(msg, "Stealth") {
		event := NewSecurityEvent(EventTypeStealthDrop, msg)
		event.RiskLevel = "MEDIUM"
		return event
	}

	if strings.Contains(msg, "OS mutation") || strings.Contains(msg, "OS fingerprint") {
		event := NewSecurityEvent(EventTypeOSMutation, msg)
		event.RiskLevel = "LOW"
		return event
	}

	if strings.Contains(msg, "egress") || strings.Contains(msg, "DLP") {
		event := NewSecurityEvent(EventTypeEgressBlock, msg)
		event.RiskLevel = "HIGH"
		return event
	}

	if strings.Contains(msg, "Connection") || strings.Contains(msg, "connection") {
		event := NewSecurityEvent(EventTypeConnection, msg)
		event.RiskLevel = "LOW"
		return event
	}

	// Default to system event
	event := NewSecurityEvent(EventTypeSystem, msg)
	event.RiskLevel = "INFO"
	return event
}

// LogEvent logs a structured security event
func (m *Manager) LogEvent(event *SecurityEvent) {
	// Send to dashboard as formatted message
	if m.outputMode == config.OutputModeDashboard || m.outputMode == config.OutputModeBoth {
		if m.dashboardChan != nil {
			msg := fmt.Sprintf("[%s] %s", event.EventType, event.Message)
			if event.SourceIP != "" {
				msg += fmt.Sprintf(" | IP: %s", event.SourceIP)
			}
			if event.Command != "" {
				msg += fmt.Sprintf(" | CMD: %s", event.Command)
			}
			select {
			case m.dashboardChan <- msg:
			default:
			}
		}
	}

	// Send to ELK
	if (m.outputMode == config.OutputModeELK || m.outputMode == config.OutputModeBoth) && m.elkExporter != nil {
		if err := m.elkExporter.Export(event.ToMap()); err != nil {
			log.Printf("[ELK] Failed to export event: %v", err)
		}
	}
}

// Close closes the logger manager
func (m *Manager) Close() error {
	close(m.logChan)
	if m.elkExporter != nil {
		return m.elkExporter.Close()
	}
	return nil
}


