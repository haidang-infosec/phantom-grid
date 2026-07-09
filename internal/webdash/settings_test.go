package webdash

import (
	"os"
	"testing"
)

func TestDefaultSettings(t *testing.T) {
	s := DefaultSettings()
	if s.AgentIdentifier != "Phantom-Node-Alpha" {
		t.Errorf("Expected default AgentIdentifier to be 'Phantom-Node-Alpha'")
	}
	if !s.StealthMode {
		t.Errorf("Expected default StealthMode to be true")
	}
}

func TestLoadSaveSettings(t *testing.T) {
	// Temporarily override the settings file path for testing
	originalFile := settingsFile
	settingsFile = "test_settings.json"
	defer func() {
		os.Remove(settingsFile)
		settingsFile = originalFile
	}()

	// Create custom settings
	s := DefaultSettings()
	s.AgentIdentifier = "Test-Node-1"
	s.SpaTriggerPort = 9999

	// Save settings
	err := SaveSettings(s)
	if err != nil {
		t.Fatalf("SaveSettings failed: %v", err)
	}

	// Load settings
	loaded := LoadSettings()
	if loaded.AgentIdentifier != "Test-Node-1" {
		t.Errorf("Expected AgentIdentifier 'Test-Node-1', got '%s'", loaded.AgentIdentifier)
	}
	if loaded.SpaTriggerPort != 9999 {
		t.Errorf("Expected SpaTriggerPort 9999, got %d", loaded.SpaTriggerPort)
	}

	// Remove file and test loading default fallback
	os.Remove(settingsFile)
	fallback := LoadSettings()
	if fallback.AgentIdentifier != "Phantom-Node-Alpha" {
		t.Errorf("Expected fallback to default settings")
	}
}
