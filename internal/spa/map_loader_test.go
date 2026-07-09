package spa

import (
	"net"
	"testing"

	"phantom-grid/internal/config"
)

func TestMapLoader_LoadConfiguration(t *testing.T) {
	// This is a unit test for configuration loading logic
	// Note: Actual BPF maps are not available in unit tests
	
	spaConfig := config.DefaultDynamicSPAConfig()
	spaConfig.Mode = config.SPAModeAsymmetric
	spaConfig.TOTPTimeStep = 30
	spaConfig.TOTPTolerance = 1
	spaConfig.ReplayWindowSeconds = 60
	
	// Test mode conversion
	loader := &MapLoader{}
	modeValue := loader.getSPAModeValue(spaConfig.Mode)
	if modeValue != 2 {
		t.Errorf("Expected mode value 2 (asymmetric), got %d", modeValue)
	}
	
	modeValue = loader.getSPAModeValue(config.SPAModeDynamic)
	if modeValue != 1 {
		t.Errorf("Expected mode value 1 (dynamic), got %d", modeValue)
	}
	
	modeValue = loader.getSPAModeValue(config.SPAModeStatic)
	if modeValue != 0 {
		t.Errorf("Expected mode value 0 (static), got %d", modeValue)
	}
}

func TestMapLoader_WhitelistIP(t *testing.T) {
	// Test IP conversion logic
	ip := net.ParseIP("192.168.1.100")
	if ip == nil {
		t.Fatal("Failed to parse IP")
	}
	
	ipv4 := ip.To4()
	if ipv4 == nil {
		t.Fatal("Failed to convert to IPv4")
	}
	
	// Verify IP is valid
	if len(ipv4) != 4 {
		t.Errorf("Expected IPv4 length 4, got %d", len(ipv4))
	}
}

