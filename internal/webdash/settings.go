package webdash

import (
	"encoding/json"
	"os"
	"sync"
)

// Settings represents the system configuration exposed via the web dashboard.
type Settings struct {
	AgentIdentifier  string `json:"agent_identifier"`
	MirageEnabled    bool   `json:"mirage_enabled"`
	LogRotation      string `json:"log_rotation"`
	ProtectedIf      string `json:"protected_if"`
	StealthMode      bool   `json:"stealth_mode"`
	EbpfTimeoutSec   int    `json:"ebpf_timeout_sec"`
	SpaTriggerPort   int    `json:"spa_trigger_port"`
	SpaWhitelistSec  int    `json:"spa_whitelist_sec"`
	SpaClockSkewSec  int    `json:"spa_clock_skew_sec"`
}

var (
	settingsMu sync.RWMutex
	settingsFile = "settings.json"
)

// DefaultSettings returns a baseline configuration.
func DefaultSettings() *Settings {
	return &Settings{
		AgentIdentifier: "Phantom-Node-Alpha",
		MirageEnabled:   true,
		LogRotation:     "100MB",
		ProtectedIf:     "eth0",
		StealthMode:     true,
		EbpfTimeoutSec:  3600,
		SpaTriggerPort:  62201,
		SpaWhitelistSec: 300,
		SpaClockSkewSec: 30,
	}
}

// LoadSettings reads settings from the local file or returns defaults.
func LoadSettings() *Settings {
	settingsMu.RLock()
	defer settingsMu.RUnlock()

	data, err := os.ReadFile(settingsFile)
	if err != nil {
		return DefaultSettings()
	}

	var s Settings
	if err := json.Unmarshal(data, &s); err != nil {
		return DefaultSettings()
	}

	return &s
}

// SaveSettings writes the settings to the local file.
func SaveSettings(s *Settings) error {
	settingsMu.Lock()
	defer settingsMu.Unlock()

	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(settingsFile, data, 0644)
}
