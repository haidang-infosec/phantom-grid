package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"text/template"

	"phantom-grid/internal/config"
)

const ebpfHeaderTemplate = `// AUTO-GENERATED FILE - DO NOT EDIT MANUALLY
// This file is generated from internal/config/config.go and ports.go
// Run 'make generate-config' to regenerate

// Core Ports
#define HONEYPOT_PORT {{.Constants.HoneypotPort}}
#define SSH_PORT {{.Constants.SSHPort}}

// SPA Configuration
#define SPA_MAGIC_PORT {{.Constants.SPAMagicPort}}
#define SPA_SECRET_TOKEN "{{.Constants.SPASecretToken}}"
#define SPA_TOKEN_LEN {{.Constants.SPATokenLen}}
#define SPA_WHITELIST_DURATION_NS ({{.Constants.SPAWhitelistDuration}}ULL * 1000000000ULL) // {{.Constants.SPAWhitelistDuration}} seconds in nanoseconds

// OS Fingerprint Values (TTL)
#define TTL_WINDOWS {{.Constants.TTLWindows}}
#define TTL_LINUX {{.Constants.TTLLinux}}
#define TTL_FREEBSD {{.Constants.TTLFreeBSD}}
#define TTL_SOLARIS {{.Constants.TTLSolaris}}

// OS Fingerprint Values (Window Size)
#define WINDOW_WINDOWS {{.Constants.WindowWindows}}
#define WINDOW_LINUX {{.Constants.WindowLinux}}
#define WINDOW_FREEBSD {{.Constants.WindowFreeBSD}}

// Egress DLP Configuration
#define MAX_PAYLOAD_SCAN {{.Constants.MaxPayloadScan}}

// Critical asset ports protected by Phantom Protocol (default: DROP all traffic)
// Generated from CriticalPortDefinitions in internal/config/ports.go
{{range .CriticalPorts}}
#define {{.Alias}} {{.Port}}  // {{.Name}} - {{.Description}}
{{end}}

// Fake ports for honeypot deception (The Mirage)
// Generated from FakePortDefinitions in internal/config/ports.go
{{range .FakePorts}}
#define {{.Alias}} {{.Port}}  // {{.Name}} - {{.Description}}
{{end}}
`

const ebpfFunctionTemplate = `// AUTO-GENERATED FUNCTION - DO NOT EDIT MANUALLY
// This function is generated from internal/config/ports.go
// Run 'make generate-config' to regenerate

static __always_inline int is_critical_asset_port(__be16 port) {
    __u16 p = bpf_ntohs(port);
    
{{range .Categories}}
    // {{.Name}}
{{range .Ports}}
    if (p == {{.Alias}}) return 1;
{{end}}
{{end}}
    
    return 0;
}

static __always_inline int is_fake_port(__be16 port) {
    __u16 p = bpf_ntohs(port);
    
{{range .FakePorts}}
    if (p == {{.Alias}}) return 1;
{{end}}
    
    return 0;
}
`

type CategoryGroup struct {
	Name  string
	Ports []config.PortDefinition
}

func main() {
	// Custom usage function
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Config Generator - Generate eBPF Configuration from Go Config\n\n")
		fmt.Fprintf(os.Stderr, "Usage: %s [options]\n\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "This tool reads port definitions from internal/config/ports.go and\n")
		fmt.Fprintf(os.Stderr, "generates eBPF C header files (phantom_ports.h) and functions\n")
		fmt.Fprintf(os.Stderr, "(phantom_ports_functions.c) for use in eBPF programs.\n\n")
		fmt.Fprintf(os.Stderr, "Options:\n")
		flag.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\nExamples:\n")
		fmt.Fprintf(os.Stderr, "  # Generate eBPF configuration\n")
		fmt.Fprintf(os.Stderr, "  %s\n\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  # Or use make\n")
		fmt.Fprintf(os.Stderr, "  make generate-config\n\n")
		fmt.Fprintf(os.Stderr, "Output files:\n")
		fmt.Fprintf(os.Stderr, "  - internal/ebpf/programs/phantom_ports.h\n")
		fmt.Fprintf(os.Stderr, "  - internal/ebpf/programs/phantom_ports_functions.c\n")
	}

	helpFlag := flag.Bool("h", false, "Show help message")
	helpFlag2 := flag.Bool("help", false, "Show help message")
	flag.Parse()

	// Show help if requested
	if *helpFlag || *helpFlag2 {
		flag.Usage()
		os.Exit(0)
	}

	// Validate configuration
	if err := config.ValidatePorts(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: Port validation failed: %v\n", err)
		os.Exit(1)
	}

	// Group critical ports by category
	categoryMap := make(map[string][]config.PortDefinition)
	for _, def := range config.CriticalPortDefinitions {
		categoryMap[def.Category] = append(categoryMap[def.Category], def)
	}

	// Sort categories and ports within categories
	var categories []CategoryGroup
	for cat, ports := range categoryMap {
		sort.Slice(ports, func(i, j int) bool {
			return ports[i].Port < ports[j].Port
		})
		categories = append(categories, CategoryGroup{
			Name:  getCategoryName(cat),
			Ports: ports,
		})
	}
	sort.Slice(categories, func(i, j int) bool {
		return categories[i].Name < categories[j].Name
	})

	// Sort fake ports
	fakePorts := make([]config.PortDefinition, len(config.FakePortDefinitions))
	copy(fakePorts, config.FakePortDefinitions)
	sort.Slice(fakePorts, func(i, j int) bool {
		return fakePorts[i].Port < fakePorts[j].Port
	})

	// Get eBPF constants
	constants := config.GetEBPFConstants()

	// Generate eBPF header defines
	generateEBPFHeader(categories, fakePorts, constants)

	// Generate eBPF function
	generateEBPFFunction(categories, fakePorts)

	fmt.Println("Configuration generation complete!")
	fmt.Printf("Generated %d critical port definitions\n", len(config.CriticalPortDefinitions))
	fmt.Printf("Generated %d fake port definitions\n", len(config.FakePortDefinitions))
}

func generateEBPFHeader(categories []CategoryGroup, fakePorts []config.PortDefinition, constants config.EBFPConstants) {
	tmpl, err := template.New("ebpfHeader").Parse(ebpfHeaderTemplate)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing template: %v\n", err)
		os.Exit(1)
	}

	outputPath := filepath.Join("internal", "ebpf", "programs", "phantom_ports.h")
	file, err := os.Create(outputPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error creating file: %v\n", err)
		os.Exit(1)
	}
	defer file.Close()

	// Collect all critical ports
	var allCriticalPorts []config.PortDefinition
	for _, cat := range categories {
		allCriticalPorts = append(allCriticalPorts, cat.Ports...)
	}
	sort.Slice(allCriticalPorts, func(i, j int) bool {
		return allCriticalPorts[i].Port < allCriticalPorts[j].Port
	})

	data := struct {
		Constants     config.EBFPConstants
		CriticalPorts []config.PortDefinition
		FakePorts     []config.PortDefinition
	}{
		Constants:     constants,
		CriticalPorts: allCriticalPorts,
		FakePorts:     fakePorts,
	}

	if err := tmpl.Execute(file, data); err != nil {
		fmt.Fprintf(os.Stderr, "Error executing template: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Generated: %s\n", outputPath)
}

func generateEBPFFunction(categories []CategoryGroup, fakePorts []config.PortDefinition) {
	tmpl, err := template.New("ebpfFunction").Parse(ebpfFunctionTemplate)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing template: %v\n", err)
		os.Exit(1)
	}

	outputPath := filepath.Join("internal", "ebpf", "programs", "phantom_ports_functions.c")
	file, err := os.Create(outputPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error creating file: %v\n", err)
		os.Exit(1)
	}
	defer file.Close()

	data := struct {
		Categories []CategoryGroup
		FakePorts  []config.PortDefinition
	}{
		Categories: categories,
		FakePorts:  fakePorts,
	}

	if err := tmpl.Execute(file, data); err != nil {
		fmt.Fprintf(os.Stderr, "Error executing template: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Generated: %s\n", outputPath)
}

func getCategoryName(cat string) string {
	names := map[string]string{
		config.CategoryCore:        "Core Services",
		config.CategoryDatabase:    "Databases",
		config.CategoryAdmin:       "Admin Panels & Management",
		config.CategoryRemote:      "Remote Access",
		config.CategoryContainer:   "Container Services",
		config.CategoryApplication: "Application Frameworks",
		config.CategoryDirectory:   "Directory Services",
		config.CategoryCache:       "Cache Services",
		config.CategoryFile:        "File Services",
		config.CategoryMessaging:   "Messaging Protocols",
	}
	if name, ok := names[cat]; ok {
		return name
	}
	return strings.Title(cat)
}
