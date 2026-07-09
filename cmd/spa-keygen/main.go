package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"phantom-grid/internal/config"
)

func main() {
	// Custom usage function
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "SPA Key Generator - Generate Ed25519 Key Pair for Dynamic SPA\n\n")
		fmt.Fprintf(os.Stderr, "Usage: %s [options]\n\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "Options:\n")
		flag.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\nExamples:\n")
		fmt.Fprintf(os.Stderr, "  # Generate keys in default directory (./keys)\n")
		fmt.Fprintf(os.Stderr, "  %s\n\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  # Generate keys in custom directory\n")
		fmt.Fprintf(os.Stderr, "  %s -dir /etc/phantom-grid/keys\n\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  # Overwrite existing keys\n")
		fmt.Fprintf(os.Stderr, "  %s -force\n\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "Output files:\n")
		fmt.Fprintf(os.Stderr, "  - spa_public.key  (32 bytes) - Keep on server\n")
		fmt.Fprintf(os.Stderr, "  - spa_private.key (64 bytes) - Distribute to clients securely\n")
	}

	keyDir := flag.String("dir", "./keys", "Directory to save keys")
	force := flag.Bool("force", false, "Overwrite existing keys")
	helpFlag := flag.Bool("h", false, "Show help message")
	helpFlag2 := flag.Bool("help", false, "Show help message")
	
	flag.Parse()

	// Show help if requested
	if *helpFlag || *helpFlag2 {
		flag.Usage()
		os.Exit(0)
	}

	// Check if keys already exist
	publicKeyPath := filepath.Join(*keyDir, "spa_public.key")
	privateKeyPath := filepath.Join(*keyDir, "spa_private.key")

	if !*force {
		if _, err := os.Stat(publicKeyPath); err == nil {
			fmt.Fprintf(os.Stderr, "Error: Keys already exist at %s\n", *keyDir)
			fmt.Fprintf(os.Stderr, "Use -force to overwrite\n")
			os.Exit(1)
		}
	}

	// Generate Ed25519 key pair
	fmt.Println("Generating Ed25519 key pair...")
	publicKey, privateKey, err := config.GenerateEd25519Keys()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error generating keys: %v\n", err)
		os.Exit(1)
	}

	// Save keys
	if err := config.SaveKeysToFile(publicKey, privateKey, *keyDir); err != nil {
		fmt.Fprintf(os.Stderr, "Error saving keys: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Keys generated successfully!\n")
	fmt.Printf("Public key:  %s\n", publicKeyPath)
	fmt.Printf("Private key: %s\n", privateKeyPath)
	fmt.Printf("\n")
	fmt.Printf("IMPORTANT: Keep the private key secure! It should only be on client machines.\n")
	fmt.Printf("The public key will be loaded into the server's eBPF maps.\n")
}

