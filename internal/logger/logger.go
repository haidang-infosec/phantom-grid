package logger

import (
	"log/slog"
	"os"
	"sync"
	"time"
)

// AttackLog is the structured format for attack logging
type AttackLog struct {
	Timestamp  string `json:"timestamp"`
	AttackerIP string `json:"src_ip"`
	Command    string `json:"command"`
	RiskLevel  string `json:"risk_level"`
}

var (
	LogChannel = make(chan string, 100)
	
	once       sync.Once
	auditLogger *slog.Logger
)

func initAuditLogger() {
	if err := os.MkdirAll("logs", 0o755); err != nil {
		return
	}
	file, err := os.OpenFile("logs/audit.json", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return
	}
	
	// Use slog with JSON handler for high-performance structured logging
	handler := slog.NewJSONHandler(file, nil)
	auditLogger = slog.New(handler)
}

// LogAttack writes a structured AttackLog entry to disk
func LogAttack(ip string, cmd string) {
	once.Do(initAuditLogger)
	
	if auditLogger != nil {
		auditLogger.Info("TRAP_HIT",
			slog.String("timestamp", time.Now().Format(time.RFC3339)),
			slog.String("src_ip", ip),
			slog.String("command", cmd),
			slog.String("risk_level", "HIGH"),
		)
	}
}
