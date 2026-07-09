package config

import (
	"testing"
)

func TestValidatePorts(t *testing.T) {
	if err := ValidatePorts(); err != nil {
		t.Fatalf("Port validation failed: %v", err)
	}
}

func TestGetCriticalPorts(t *testing.T) {
	ports := GetCriticalPorts()
	if len(ports) == 0 {
		t.Fatal("CriticalPorts should not be empty")
	}

	// Check for duplicates
	seen := make(map[int]bool)
	for _, port := range ports {
		if seen[port] {
			t.Errorf("Duplicate port found: %d", port)
		}
		seen[port] = true

		// Validate port range
		if port < 1 || port > 65535 {
			t.Errorf("Invalid port range: %d", port)
		}
	}
}

func TestGetFakePorts(t *testing.T) {
	ports := GetFakePorts()
	if len(ports) == 0 {
		t.Fatal("FakePorts should not be empty")
	}

	// Check for duplicates
	seen := make(map[int]bool)
	for _, port := range ports {
		if seen[port] {
			t.Errorf("Duplicate port found: %d", port)
		}
		seen[port] = true

		// Validate port range
		if port < 1 || port > 65535 {
			t.Errorf("Invalid port range: %d", port)
		}
	}
}

func TestFindPortDefinition(t *testing.T) {
	// Test finding a critical port
	def := FindPortDefinition(22) // SSH
	if def == nil {
		t.Fatal("Should find SSH port definition")
	}
	if def.Port != 22 || def.Name != "SSH" {
		t.Errorf("Wrong port definition: got %+v", def)
	}

	// Test finding a fake port
	def = FindPortDefinition(80) // HTTP
	if def == nil {
		t.Fatal("Should find HTTP port definition")
	}
	if def.Port != 80 || def.Name != "HTTP" {
		t.Errorf("Wrong port definition: got %+v", def)
	}

	// Test non-existent port
	def = FindPortDefinition(99999)
	if def != nil {
		t.Errorf("Should not find definition for port 99999: got %+v", def)
	}
}

func TestPortDefinitionsConsistency(t *testing.T) {
	// Verify CriticalPorts matches CriticalPortDefinitions
	criticalPorts := GetCriticalPorts()
	if len(criticalPorts) != len(CriticalPortDefinitions) {
		t.Errorf("CriticalPorts length (%d) != CriticalPortDefinitions length (%d)",
			len(criticalPorts), len(CriticalPortDefinitions))
	}

	// Verify FakePorts matches FakePortDefinitions
	fakePorts := GetFakePorts()
	if len(fakePorts) != len(FakePortDefinitions) {
		t.Errorf("FakePorts length (%d) != FakePortDefinitions length (%d)",
			len(fakePorts), len(FakePortDefinitions))
	}

	// Check that all critical ports have valid definitions
	for _, port := range criticalPorts {
		def := FindPortDefinition(port)
		if def == nil {
			t.Errorf("No definition found for critical port: %d", port)
		}
	}

	// Check that all fake ports have valid definitions
	for _, port := range fakePorts {
		def := FindPortDefinition(port)
		if def == nil {
			t.Errorf("No definition found for fake port: %d", port)
		}
	}
}

func TestPortAliases(t *testing.T) {
	// Verify all critical ports have aliases
	for _, def := range CriticalPortDefinitions {
		if def.Alias == "" {
			t.Errorf("Port %d (%s) missing alias", def.Port, def.Name)
		}
	}

	// Verify all fake ports have aliases
	for _, def := range FakePortDefinitions {
		if def.Alias == "" {
			t.Errorf("Port %d (%s) missing alias", def.Port, def.Name)
		}
	}
}

