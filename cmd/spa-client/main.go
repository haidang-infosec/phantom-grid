package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"

	"phantom-grid/internal/config"
	"phantom-grid/pkg/spa"
)

func main() {
	// Custom usage function
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "SPA Client - Single Packet Authorization Client\n\n")
		fmt.Fprintf(os.Stderr, "Usage: %s [options]\n\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "Options:\n")
		flag.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\nExamples:\n")
		fmt.Fprintf(os.Stderr, "  # Static SPA (legacy)\n")
		fmt.Fprintf(os.Stderr, "  %s -server 192.168.1.100\n\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  # Dynamic Asymmetric SPA (auto-detects keys)\n")
		fmt.Fprintf(os.Stderr, "  %s -server 192.168.1.100 -mode asymmetric\n\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  # With custom key paths\n")
		fmt.Fprintf(os.Stderr, "  %s -server 192.168.1.100 -mode asymmetric -key ~/.phantom-grid/spa_private.key -totp ~/.phantom-grid/totp_secret.txt\n\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "Note: Keys are auto-detected from default locations if not specified.\n")
		fmt.Fprintf(os.Stderr, "See docs/GETTING_STARTED.md for detailed instructions.\n")
	}

	// Parse command line arguments
	serverIP := flag.String("server", "", "Server IP address (required)")
	mode := flag.String("mode", "static", "SPA mode: 'static', 'dynamic', or 'asymmetric'")
	keyPath := flag.String("key", "", "Path to private key file (auto-detected if not specified). Searches: ./keys/spa_private.key, ~/.phantom-grid/spa_private.key")
	totpSecretPath := flag.String("totp", "", "Path to TOTP secret file (auto-detected if not specified). Searches: ./keys/totp_secret.txt, ~/.phantom-grid/totp_secret.txt")
	staticTokenFlag := flag.String("static-token", "", "Static SPA token (for static mode only). If not provided, uses default")
	helpFlag := flag.Bool("h", false, "Show help message")
	helpFlag2 := flag.Bool("help", false, "Show help message")
	
	flag.Parse()

	// Show help if requested
	if *helpFlag || *helpFlag2 {
		flag.Usage()
		os.Exit(0)
	}

	// Validate server IP
	if *serverIP == "" {
		flag.Usage()
		os.Exit(1)
	}

	// Handle static mode (legacy)
	if *mode == "static" {
		var token string
		if *staticTokenFlag != "" {
			token = *staticTokenFlag
			fmt.Printf("[*] Using custom static token (length: %d)\n", len(token))
		} else {
			// Prompt for token
			fmt.Print("[*] Enter static token (press Enter for default): ")
			var input string
			fmt.Scanln(&input)
			if input != "" {
				token = input
			} else {
				token = config.SPASecretToken
			}
		}

		client := spa.NewClientWithToken(*serverIP, token)
		fmt.Printf("[*] Sending Static SPA Magic Packet to %s:%d...\n", *serverIP, config.SPAMagicPort)
		if err := client.SendMagicPacket(); err != nil {
			fmt.Printf("[!] Error: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("[*] Sent %d bytes\n", len(token))
		fmt.Println("[+] Magic Packet sent successfully!")
		fmt.Printf("[+] Your IP has been whitelisted for %d seconds\n", config.SPAWhitelistDuration)
		fmt.Println("[+] You can now connect to protected services:")
		fmt.Printf("    ssh user@%s\n", *serverIP)
		fmt.Printf("    ftp %s\n", *serverIP)
		fmt.Println("\n[*] Note: Whitelist expires in 30 seconds")
		return
	}

	// Handle dynamic modes
	spaConfig := config.DefaultDynamicSPAConfig()

	// Set mode
	switch *mode {
	case "dynamic":
		spaConfig.Mode = config.SPAModeDynamic
	case "asymmetric":
		spaConfig.Mode = config.SPAModeAsymmetric
	default:
		log.Fatalf("Invalid mode: %s. Use 'static', 'dynamic', or 'asymmetric'", *mode)
	}

	// Load private key for asymmetric mode
	if spaConfig.Mode == config.SPAModeAsymmetric {
		if *keyPath == "" {
			// Try default locations automatically
			defaultPaths := []string{
				"./keys/spa_private.key",
				filepath.Join(os.Getenv("HOME"), ".phantom-grid", "spa_private.key"),
				filepath.Join(os.Getenv("USERPROFILE"), ".phantom-grid", "spa_private.key"), // Windows
			}
			for _, path := range defaultPaths {
				if _, err := os.Stat(path); err == nil {
					*keyPath = path
					fmt.Printf("[*] Auto-detected private key: %s\n", path)
					break
				}
			}
		}

		if *keyPath == "" {
			fmt.Fprintf(os.Stderr, "Error: Private key required for asymmetric mode.\n")
			fmt.Fprintf(os.Stderr, "Searched in:\n")
			fmt.Fprintf(os.Stderr, "  - ./keys/spa_private.key\n")
			fmt.Fprintf(os.Stderr, "  - ~/.phantom-grid/spa_private.key\n")
			fmt.Fprintf(os.Stderr, "  - $USERPROFILE/.phantom-grid/spa_private.key (Windows)\n")
			fmt.Fprintf(os.Stderr, "\nUse -key flag to specify key path, or copy key to one of the above locations.\n")
			os.Exit(1)
		}

		fmt.Printf("[*] Loading private key from %s...\n", *keyPath)
		_, privateKey, err := config.LoadKeysFromFile("", *keyPath)
		if err != nil {
			log.Fatalf("Failed to load private key: %v\nMake sure the key file exists and has correct permissions (chmod 600)", err)
		}
		spaConfig.PrivateKey = privateKey
		fmt.Println("[+] Private key loaded")
	}

	// Load TOTP secret - try auto-detect if not provided
	if spaConfig.Mode == config.SPAModeAsymmetric || spaConfig.Mode == config.SPAModeDynamic {
		if *totpSecretPath == "" {
			// Try default locations automatically
			defaultTotpPaths := []string{
				"./keys/totp_secret.txt",
				filepath.Join(os.Getenv("HOME"), ".phantom-grid", "totp_secret.txt"),
				filepath.Join(os.Getenv("USERPROFILE"), ".phantom-grid", "totp_secret.txt"), // Windows
			}
			for _, path := range defaultTotpPaths {
				if _, err := os.Stat(path); err == nil {
					*totpSecretPath = path
					fmt.Printf("[*] Auto-detected TOTP secret: %s\n", path)
					break
				}
			}
		}

		if *totpSecretPath != "" {
			fmt.Printf("[*] Loading TOTP secret from %s...\n", *totpSecretPath)
			totpSecret, err := os.ReadFile(*totpSecretPath)
			if err != nil {
				log.Fatalf("Failed to load TOTP secret: %v\nMake sure the secret file exists", err)
			}
			// Remove newline if present
			if len(totpSecret) > 0 && totpSecret[len(totpSecret)-1] == '\n' {
				totpSecret = totpSecret[:len(totpSecret)-1]
			}
			spaConfig.TOTPSecret = totpSecret
			fmt.Println("[+] TOTP secret loaded")
		} else {
			fmt.Println("[!] Warning: TOTP secret not found. Authentication may fail if server requires it.")
		}
	}

	// Create dynamic client
	fmt.Printf("[*] Creating %s SPA client for server %s...\n", *mode, *serverIP)
	client, err := spa.NewDynamicClient(*serverIP, spaConfig)
	if err != nil {
		log.Fatalf("Failed to create client: %v", err)
	}

	// Send magic packet
	fmt.Printf("[*] Sending %s SPA packet to %s:%d...\n", *mode, *serverIP, config.SPAMagicPort)
	if err := client.SendMagicPacket(); err != nil {
		log.Fatalf("Failed to send packet: %v", err)
	}

	fmt.Println("[+] SPA packet sent successfully!")
	fmt.Printf("[+] Your IP has been whitelisted for %d seconds\n", config.SPAWhitelistDuration)
	fmt.Println("[+] You can now connect to protected services:")
	fmt.Printf("    ssh user@%s\n", *serverIP)
	fmt.Printf("    ftp %s\n", *serverIP)
	fmt.Println("\n[*] Note: Whitelist expires in 30 seconds")
}
