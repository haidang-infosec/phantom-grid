package network

import (
	"fmt"
	"log"
	"net"
	"strings"
)

// DetectInterface detects and returns the appropriate network interface
func DetectInterface(specifiedInterface string) (*net.Interface, string, error) {
	// List all interfaces for debugging
	allInterfaces, _ := net.Interfaces()
	log.Printf("[DEBUG] Available interfaces:")
	for _, iface := range allInterfaces {
		addrs, _ := iface.Addrs()
		isLoopback := (iface.Flags & net.FlagLoopback) != 0
		log.Printf("[DEBUG]   - %s (index: %d, loopback: %v, addrs: %d)", iface.Name, iface.Index, isLoopback, len(addrs))
		for _, addr := range addrs {
			log.Printf("[DEBUG]     IP: %s", addr.String())
		}
	}

	if specifiedInterface != "" {
		return getInterfaceByName(specifiedInterface)
	}

	return autoDetectInterface()
}

func getInterfaceByName(name string) (*net.Interface, string, error) {
	iface, err := net.InterfaceByName(name)
	if err != nil {
		return nil, "", fmt.Errorf("failed to find interface '%s': %w", name, err)
	}

	log.Printf("[*] Using user-specified interface: %s (index: %d)", name, iface.Index)
	addrs, _ := iface.Addrs()
	for _, addr := range addrs {
		log.Printf("[*]   IP: %s", addr.String())
	}

	return iface, name, nil
}

func autoDetectInterface() (*net.Interface, string, error) {
	log.Printf("[*] No interface specified, auto-detecting...")

	interfaceNames := []string{"wlx00127b2163a6", "wlan0", "ens33", "eth0", "enp0s3", "enp0s8", "enp0s9", "eth1"}
	var foundExternal bool
	var selectedIface *net.Interface
	var selectedName string

	// Try to find WiFi interface by pattern
	wifiInterfaces, _ := net.Interfaces()
	for _, candidateIface := range wifiInterfaces {
		if strings.HasPrefix(candidateIface.Name, "wlx") ||
			strings.HasPrefix(candidateIface.Name, "wlan") ||
			strings.HasPrefix(candidateIface.Name, "wlp") {
			addrs, _ := candidateIface.Addrs()
			if len(addrs) > 0 {
				isLoopback := (candidateIface.Flags & net.FlagLoopback) != 0
				if !isLoopback {
					ifaceCopy := candidateIface
					selectedIface = &ifaceCopy
					selectedName = candidateIface.Name
					foundExternal = true
					log.Printf("[*] Found WiFi interface: %s (index: %d)", selectedName, selectedIface.Index)
					for _, addr := range addrs {
						log.Printf("[*]   IP: %s", addr.String())
					}
					break
				}
			}
		}
	}

	// If WiFi not found, try exact interface names
	if !foundExternal {
		for _, name := range interfaceNames {
			iface, err := net.InterfaceByName(name)
			if err == nil {
				addrs, _ := iface.Addrs()
				if len(addrs) > 0 {
					isLoopback := (iface.Flags & net.FlagLoopback) != 0
					if !isLoopback {
						selectedIface = iface
						selectedName = name
						foundExternal = true
						log.Printf("[*] Using network interface: %s (index: %d)", selectedName, selectedIface.Index)
						for _, addr := range addrs {
							log.Printf("[*]   IP: %s", addr.String())
						}
						break
					} else {
						log.Printf("[DEBUG] Interface %s is loopback, skipping", name)
					}
				} else {
					log.Printf("[DEBUG] Interface %s has no IP addresses, skipping", name)
				}
			} else {
				log.Printf("[DEBUG] Interface %s not found: %v", name, err)
			}
		}
	}

	// Fallback to loopback
	if !foundExternal {
		iface, err := net.InterfaceByName("lo")
		if err == nil {
			selectedIface = iface
			selectedName = "lo"
			log.Printf("[*] Using loopback interface: %s (index: %d) - for local testing only", selectedName, selectedIface.Index)
			log.Printf("[!] WARNING: For production, attach to external interface (eth0, ens33, etc.)")
			log.Printf("[!] WARNING: Traffic from external hosts (Kali) will NOT be captured on loopback!")
		}
	}

	if selectedIface == nil {
		return nil, "", fmt.Errorf("no suitable network interface found")
	}

	return selectedIface, selectedName, nil
}
