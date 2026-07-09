package config

// SPA Configuration
var SPAMagicPort = 1337

const (
	SPASecretToken       = "PHANTOM_GRID_SPA_2025"
	SPATokenLen          = 21
	SPAWhitelistDuration = 30
)

// Network Configuration
const (
	HoneypotPort = 9999
	SSHPort      = 22
)

// CriticalPorts are ports protected by Phantom Protocol (SPA required)
// These ports will be DROPPED unless IP is whitelisted via SPA Magic Packet
// IMPORTANT: This is auto-generated from CriticalPortDefinitions in ports.go
// To add/modify ports, update CriticalPortDefinitions in ports.go and run: make generate-config
var CriticalPorts = GetCriticalPorts()

// FakePorts are ports for honeypot deception (The Mirage)
// IMPORTANT: This is auto-generated from FakePortDefinitions in ports.go
// To add/modify ports, update FakePortDefinitions in ports.go and run: make generate-config
var FakePorts = GetFakePorts()

// Fallback ports if honeypot port is unavailable
var FallbackPorts = []int{9998, 9997, 9996, 8888, 7777}

// OutputMode defines where logs and events are sent
type OutputMode string

const (
	OutputModeDashboard OutputMode = "dashboard" // Terminal dashboard only
	OutputModeELK       OutputMode = "elk"       // Elasticsearch only
	OutputModeBoth      OutputMode = "both"      // Both dashboard and ELK
)

// ELKConfiguration holds Elasticsearch connection settings
type ELKConfiguration struct {
	Enabled       bool
	Addresses     []string // Elasticsearch addresses (e.g., ["http://localhost:9200"])
	Index         string   // Index name (default: "phantom-grid")
	Username      string   // Optional: Basic auth username
	Password      string   // Optional: Basic auth password
	UseTLS        bool     // Enable TLS
	SkipVerify    bool     // Skip TLS certificate verification
	BatchSize     int      // Number of documents to batch before sending
	FlushInterval int      // Flush interval in seconds
}

// DefaultELKConfig returns default ELK configuration
func DefaultELKConfig() ELKConfiguration {
	return ELKConfiguration{
		Enabled:       false,
		Addresses:     []string{"http://localhost:9200"},
		Index:         "phantom-grid",
		Username:      "",
		Password:      "",
		UseTLS:        false,
		SkipVerify:    false,
		BatchSize:     100,
		FlushInterval: 5,
	}
}
