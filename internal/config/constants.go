package config

// EBPFConstants holds all eBPF-related constants
// These are used to generate C defines for eBPF programs
type EBFPConstants struct {
	// Core Ports
	HoneypotPort int
	SSHPort      int

	// SPA Configuration
	SPAMagicPort         int
	SPASecretToken       string
	SPATokenLen          int
	SPAWhitelistDuration int // in seconds

	// OS Fingerprint Values (TTL)
	TTLWindows int
	TTLLinux   int
	TTLFreeBSD int
	TTLSolaris int

	// OS Fingerprint Values (Window Size)
	WindowWindows int
	WindowLinux   int
	WindowFreeBSD int

	// Egress DLP
	MaxPayloadScan int
}

// GetEBPFConstants returns all eBPF constants
func GetEBPFConstants() EBFPConstants {
	return EBFPConstants{
		HoneypotPort:         HoneypotPort,
		SSHPort:              SSHPort,
		SPAMagicPort:         SPAMagicPort,
		SPASecretToken:       SPASecretToken,
		SPATokenLen:          SPATokenLen,
		SPAWhitelistDuration: SPAWhitelistDuration,
		TTLWindows:           128,
		TTLLinux:             64,
		TTLFreeBSD:           64,
		TTLSolaris:           255,
		WindowWindows:        65535,
		WindowLinux:          29200,
		WindowFreeBSD:        65535,
		MaxPayloadScan:       512,
	}
}
