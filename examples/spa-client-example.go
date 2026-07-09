package main

import (
	"net"
	"flag"
	"fmt"
	"log"
	"os"

	"phantom-grid/internal/config"
	"phantom-grid/pkg/spa"
)

func main() {
	// Parse command line arguments
	serverIP := flag.String("server", "", "Server IP address (required)")
	keyPath := flag.String("key", "./keys/spa_private.key", "Path to private key file")
	totpSecretPath := flag.String("totp", "./keys/totp_secret.txt", "Path to TOTP secret file")
	flag.Parse()

	if *serverIP == "" {
		flag.Usage()
		log.Fatal("Error: -server flag is required")
	}

	// Load configuration
	spaConfig := config.DefaultDynamicSPAConfig()
	spaConfig.Mode = config.SPAModeAsymmetric

	// Load private key
	fmt.Printf("Loading private key from %s...\n", *keyPath)
	_, privateKey, err := config.LoadKeysFromFile("", *keyPath)
	if err != nil {
		log.Fatalf("Failed to load private key: %v\nMake sure the key file exists and has correct permissions (chmod 600)", err)
	}
	spaConfig.PrivateKey = privateKey
	fmt.Println("✓ Private key loaded")

	// Load TOTP secret
	fmt.Printf("Loading TOTP secret from %s...\n", *totpSecretPath)
	totpSecret, err := os.ReadFile(*totpSecretPath)
	if err != nil {
		log.Fatalf("Failed to load TOTP secret: %v\nMake sure the secret file exists", err)
	}
	// Remove newline if present
	if len(totpSecret) > 0 && totpSecret[len(totpSecret)-1] == '\n' {
		totpSecret = totpSecret[:len(totpSecret)-1]
	}
	spaConfig.TOTPSecret = totpSecret
	fmt.Println("✓ TOTP secret loaded")

	// Create client
	fmt.Printf("Creating SPA client for server %s...\n", *serverIP)
	client, err := spa.NewDynamicClient(*serverIP, spaConfig, net.ParseIP("192.168.1.100"))
	if err != nil {
		log.Fatalf("Failed to create client: %v", err)
	}
	fmt.Println("✓ Client created")

	// Send magic packet
	fmt.Printf("Sending SPA packet to %s:1337...\n", *serverIP)
	if err := client.SendMagicPacket(); err != nil {
		log.Fatalf("Failed to send packet: %v", err)
	}

	fmt.Println("✓ SPA packet sent successfully!")
	fmt.Println("")
	fmt.Println("Your IP should now be whitelisted for 30 seconds.")
	fmt.Println("You can now connect to protected services (SSH, etc.)")
}

