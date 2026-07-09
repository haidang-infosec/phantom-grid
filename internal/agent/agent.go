package agent

import (
	"fmt"
	"log"
	"net"
	"os"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"phantom-grid/internal/config"
	"phantom-grid/internal/ebpf"
	"phantom-grid/internal/honeypot"
	"phantom-grid/internal/logger"
	"phantom-grid/internal/network"
	"phantom-grid/internal/spa"
)

// Agent represents the main Phantom Grid agent
type Agent struct {
	ebpfLoader  *ebpf.Loader
	iface       *net.Interface
	ifaceName   string
	honeypot    *honeypot.Honeypot
	spaManager  *spa.Manager
	logChan     chan<- string
	logManager  *logger.Manager
	spaConfig   *config.DynamicSPAConfig
	spaHandler  *spa.Handler
	staticToken string // Static token for legacy SPA mode
}

// New creates a new Agent instance
func New(interfaceName string, outputMode config.OutputMode, elkConfig config.ELKConfiguration, dashboardChan chan<- string, spaConfig *config.DynamicSPAConfig, staticToken string) (*Agent, error) {
	// Detect network interface
	iface, ifaceName, err := network.DetectInterface(interfaceName)
	if err != nil {
		return nil, fmt.Errorf("failed to detect interface: %w", err)
	}

	// Initialize eBPF loader
	ebpfLoader, err := ebpf.NewLoader()
	if err != nil {
		return nil, fmt.Errorf("failed to initialize eBPF loader: %w", err)
	}

	// Load egress program (optional)
	if err := ebpfLoader.LoadEgress(); err != nil {
		log.Printf("[!] Warning: Failed to load TC egress objects: %v", err)
		log.Printf("[!] TC Egress DLP will be disabled. Main XDP protection still active.")
	}

	// Initialize logger manager
	logManager, err := logger.NewManager(outputMode, elkConfig, dashboardChan)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize logger manager: %w", err)
	}

	agent := &Agent{
		ebpfLoader:  ebpfLoader,
		iface:       iface,
		ifaceName:   ifaceName,
		logChan:     logManager.LogChannel(),
		logManager:  logManager,
		spaConfig:   spaConfig,
		staticToken: staticToken,
	}

	return agent, nil
}

// Start initializes and starts the agent
func (a *Agent) Start() error {
	// Attach XDP
	_, err := a.ebpfLoader.AttachXDP(a.iface.Index)
	if err != nil {
		return fmt.Errorf("failed to attach XDP: %w", err)
	}
	// Note: XDP link is stored in ebpfLoader and will be closed via ebpfLoader.Close()

	log.Printf("[*] XDP attached to interface: %s (index: %d)", a.ifaceName, a.iface.Index)
	a.logChan <- fmt.Sprintf("[SYSTEM] XDP attached to interface: %s (index: %d)", a.ifaceName, a.iface.Index)

	// Attach TC Egress (if loaded)
	if a.ebpfLoader.EgressObjs != nil {
		if err := a.attachTCEgress(); err != nil {
			log.Printf("[!] Warning: Failed to attach TC egress: %v", err)
			log.Printf("[!] TC Egress DLP will be disabled. Main XDP protection still active.")
		} else {
			a.logChan <- "[SYSTEM] TC Egress Hook attached (DLP Active)"
		}
	}

	// Start SPA Manager
	spaWrapper := spa.NewWrapper(
		a.ebpfLoader.PhantomObjs.SpaAuthSuccess,
		a.ebpfLoader.PhantomObjs.SpaAuthFailed,
	)
	a.spaManager = spa.NewManager(spaWrapper, a.logChan, config.SPAWhitelistDuration)
	go a.spaManager.Start()

	// Initialize SPA handler
	if a.spaConfig != nil && a.spaConfig.Mode != config.SPAModeStatic {
		// Dynamic SPA mode
		if err := a.initDynamicSPA(); err != nil {
			log.Printf("[!] Warning: Failed to initialize dynamic SPA: %v", err)
			log.Printf("[!] Falling back to static SPA mode")
		}
	} else {
		// Static SPA mode - initialize handler with static token
		log.Printf("[SPA] Initializing static SPA handler...")
		if err := a.initStaticSPA(); err != nil {
			log.Printf("[!] Warning: Failed to initialize static SPA handler: %v", err)
			a.logChan <- fmt.Sprintf("[!] Warning: Failed to initialize static SPA handler: %v", err)
		} else {
			log.Printf("[SPA] Static SPA handler initialized successfully")
		}
	}

	// Log system info
	a.logChan <- fmt.Sprintf("[SYSTEM] SPA Magic Packet port: %d", config.SPAMagicPort)
	a.logChan <- fmt.Sprintf("[SYSTEM] SSH port %d protected - requires SPA whitelist", config.SSHPort)

	// Log interface IP addresses
	addrs, err := a.iface.Addrs()
	if err != nil {
		log.Printf("[DEBUG] Failed to get interface addresses: %v", err)
	} else {
		for _, addr := range addrs {
			a.logChan <- fmt.Sprintf("[DEBUG] Interface %s has IP: %s", a.ifaceName, addr.String())
		}
	}

	// Warn if using loopback interface
	if a.ifaceName == "lo" {
		a.logChan <- "[!] WARNING: XDP attached to LOOPBACK interface!"
		a.logChan <- "[!] WARNING: Traffic from external hosts (Kali) will NOT be captured!"
		a.logChan <- "[!] WARNING: For VMware NAT, ensure XDP attaches to external interface (ens33, eth0, etc.)"
		a.logChan <- "[!] WARNING: Check if interface detection is working correctly"
	}

	// Start Honeypot
	a.honeypot = honeypot.New(a.logChan)
	honeypotErrChan := make(chan error, 1)
	go func() {
		if err := a.honeypot.Start(); err != nil {
			honeypotErrChan <- err
			log.Printf("[!] Failed to start honeypot: %v", err)
		}
	}()

	// Check if honeypot started successfully (non-blocking)
	select {
	case err := <-honeypotErrChan:
		return fmt.Errorf("honeypot failed to start: %w", err)
	default:
		// Honeypot started successfully
	}

	return nil
}

// initDynamicSPA initializes dynamic SPA handler and loads configuration
func (a *Agent) initDynamicSPA() error {
	// Create verifier
	verifier := spa.NewVerifier(a.spaConfig)

	// Note: For now, we use the existing whitelist map
	// In a full implementation, we would need access to the dynamic SPA maps
	// This requires the dynamic SPA eBPF program (phantom_spa_dynamic.c) to be loaded
	// For now, we'll create a simplified map loader using existing maps
	
	// Create map loader (using existing maps as placeholders)
	// Note: Dynamic SPA eBPF program (phantom_spa_dynamic.c) is not yet fully integrated.
	// The dynamic SPA program needs to be compiled and loaded separately.
	// For now, we use the existing whitelist map from the main phantom program.
	mapLoader := spa.NewMapLoader(
		a.ebpfLoader.PhantomObjs.SpaWhitelist, // whitelist map
		nil, // replay map (from dynamic SPA program - not available yet)
		nil, // totp secret map (from dynamic SPA program - not available yet)
		nil, // hmac secret map (from dynamic SPA program - not available yet)
		nil, // config map (from dynamic SPA program - not available yet)
	)

	// Load configuration (if maps are available)
	if mapLoader != nil {
		if err := mapLoader.LoadConfiguration(a.spaConfig); err != nil {
			log.Printf("[!] Warning: Failed to load SPA config into maps: %v", err)
		}
	}

	// Create and start handler (static token not needed for dynamic mode)
	handler := spa.NewHandler(verifier, mapLoader, a.logChan, a.spaConfig, "")
	if err := handler.Start(); err != nil {
		return fmt.Errorf("failed to start SPA handler: %w", err)
	}

	a.spaHandler = handler
	a.logChan <- fmt.Sprintf("[SPA] Dynamic SPA initialized (mode: %s)", a.spaConfig.Mode)

	return nil
}

// initStaticSPA initializes static SPA handler with configurable token
func (a *Agent) initStaticSPA() error {
	// Create a minimal config for static mode
	staticConfig := config.DefaultDynamicSPAConfig()
	staticConfig.Mode = config.SPAModeStatic

	// Create verifier (not really used for static mode, but required by handler)
	verifier := spa.NewVerifier(staticConfig)

	// Create map loader (using existing whitelist map)
	mapLoader := spa.NewMapLoader(
		a.ebpfLoader.PhantomObjs.SpaWhitelist,
		nil, nil, nil, nil, // Dynamic SPA maps not needed for static mode
	)

	// Create and start handler with static token
	handler := spa.NewHandler(verifier, mapLoader, a.logChan, staticConfig, a.staticToken)
	if err := handler.Start(); err != nil {
		return fmt.Errorf("failed to start static SPA handler: %w", err)
	}

	a.spaHandler = handler
	if a.staticToken != "" && a.staticToken != config.SPASecretToken {
		a.logChan <- fmt.Sprintf("[SPA] Static SPA initialized with custom token (length: %d)", len(a.staticToken))
		log.Printf("[SPA] Static SPA initialized with custom token (length: %d)", len(a.staticToken))
	} else {
		a.logChan <- fmt.Sprintf("[SPA] Static SPA initialized with default token")
		log.Printf("[SPA] Static SPA initialized with default token: %s", config.SPASecretToken)
	}

	return nil
}

// attachTCEgress attaches TC egress program using netlink
func (a *Agent) attachTCEgress() error {
	_, err := netlink.LinkByIndex(a.iface.Index)
	if err != nil {
		return fmt.Errorf("could not get link: %w", err)
	}

	// Add clsact qdisc
	qdisc := &netlink.GenericQdisc{
		QdiscAttrs: netlink.QdiscAttrs{
			LinkIndex: a.iface.Index,
			Handle:    netlink.MakeHandle(0xffff, 0),
			Parent:    netlink.HANDLE_CLSACT,
		},
		QdiscType: "clsact",
	}

	if err := netlink.QdiscAdd(qdisc); err != nil && !isExist(err) {
		return fmt.Errorf("failed to add qdisc: %w", err)
	}

	// Add BPF Filter to Egress
	filter := &netlink.BpfFilter{
		FilterAttrs: netlink.FilterAttrs{
			LinkIndex: a.iface.Index,
			Parent:    netlink.HANDLE_MIN_EGRESS,
			Handle:    1,
			Protocol:  unix.ETH_P_ALL,
			Priority:  1,
		},
		Fd:           a.ebpfLoader.EgressObjs.PhantomEgressProg.FD(),
		Name:         "phantom_egress",
		DirectAction: true,
	}

	if err := netlink.FilterAdd(filter); err != nil {
		return fmt.Errorf("failed to add filter: %w", err)
	}

	return nil
}

func isExist(err error) bool {
	if err == nil {
		return false
	}
	return os.IsExist(err)
}

// GetEBPFObjects returns eBPF objects for dashboard
func (a *Agent) GetEBPFObjects() (*ebpf.PhantomObjects, *ebpf.EgressObjects) {
	return a.ebpfLoader.PhantomObjs, a.ebpfLoader.EgressObjs
}

// GetInterfaceName returns the interface name
func (a *Agent) GetInterfaceName() string {
	return a.ifaceName
}

// Close cleans up agent resources
func (a *Agent) Close() error {
	if a.spaHandler != nil {
		if err := a.spaHandler.Stop(); err != nil {
			return err
		}
	}
	if a.honeypot != nil {
		if err := a.honeypot.Close(); err != nil {
			return err
		}
	}
	if a.logManager != nil {
		if err := a.logManager.Close(); err != nil {
			return err
		}
	}
	if a.ebpfLoader != nil {
		return a.ebpfLoader.Close()
	}
	return nil
}
