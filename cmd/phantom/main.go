package main

import (
	"bufio"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"phantom-grid/internal/config"
)

var (
	menuColorReset  = "\033[0m"
	menuColorBold   = "\033[1m"
	menuColorCyan   = "\033[36m"
	menuColorGreen  = "\033[32m"
	menuColorYellow = "\033[33m"
	menuColorRed    = "\033[31m"
)

func init() {
	// Disable colors on Windows
	if runtime.GOOS == "windows" {
		menuColorReset = ""
		menuColorBold = ""
		menuColorCyan = ""
		menuColorGreen = ""
		menuColorYellow = ""
		menuColorRed = ""
	}
}

func main() {

	clearScreen()
	showBanner()

	for {
		showMainMenu()
		choice := getUserInput("Select an option: ")

		switch choice {
		case "1":
			handleKeyManagement()
		case "2":
			handleAgentManagement()
		case "3":
			handleSPATest()
		case "4":
			handleConfiguration()
		case "5":
			handleSystemInfo()
		case "6":
			handleDocumentation()
		case "0", "q", "exit":
			fmt.Println("\n" + menuColorGreen + "[+] Exiting Phantom Grid. Stay secure!" + menuColorReset)
			os.Exit(0)
		default:
			fmt.Println(menuColorRed + "[!] Invalid option. Please try again." + menuColorReset)
			pause()
		}
	}
}

func clearScreen() {
	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		cmd = exec.Command("cmd", "/c", "cls")
	} else {
		cmd = exec.Command("clear")
	}
	cmd.Stdout = os.Stdout
	cmd.Run()
}

func showBanner() {
	banner := `
` + menuColorCyan + menuColorBold + `
╔══════════════════════════════════════════════════════════════╗
║                                                              ║
║          ` + menuColorGreen + `PHANTOM GRID` + menuColorCyan + ` - Active Defense System          ║
║                                                              ║
║              Kernel-level Network Protection                 ║
║                                                              ║
╚══════════════════════════════════════════════════════════════╝
` + menuColorReset
	fmt.Print(banner)
}

func showMainMenu() {
	fmt.Println("\n" + menuColorBold + "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" + menuColorReset)
	fmt.Println(menuColorBold + "                              MAIN MENU" + menuColorReset)
	fmt.Println(menuColorBold + "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" + menuColorReset)
	fmt.Println()
	fmt.Println("  " + menuColorCyan + "[1]" + menuColorReset + " Key Management")
	fmt.Println("     Generate and manage SPA keys")
	fmt.Println()
	fmt.Println("  " + menuColorCyan + "[2]" + menuColorReset + " Agent Management")
	fmt.Println("     Start, stop, and configure the agent")
	fmt.Println()
	fmt.Println("  " + menuColorCyan + "[3]" + menuColorReset + " SPA Testing")
	fmt.Println("     Test Single Packet Authorization")
	fmt.Println()
	fmt.Println("  " + menuColorCyan + "[4]" + menuColorReset + " Configuration")
	fmt.Println("     Configure ports, output modes, and settings")
	fmt.Println()
	fmt.Println("  " + menuColorCyan + "[5]" + menuColorReset + " System Information")
	fmt.Println("     View system status and statistics")
	fmt.Println()
	fmt.Println("  " + menuColorCyan + "[6]" + menuColorReset + " Documentation")
	fmt.Println("     View documentation and guides")
	fmt.Println()
	fmt.Println("  " + menuColorYellow + "[0]" + menuColorReset + " Exit")
	fmt.Println()
}

func handleKeyManagement() {
	for {
		clearScreen()
		fmt.Println(menuColorBold + "\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" + menuColorReset)
		fmt.Println(menuColorBold + "                         KEY MANAGEMENT" + menuColorReset)
		fmt.Println(menuColorBold + "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" + menuColorReset)
		fmt.Println()
		fmt.Println("  [1] Generate Ed25519 Key Pair")
		fmt.Println("  [2] Generate TOTP Secret")
		fmt.Println("  [3] View Key Status")
		fmt.Println("  [4] Copy Keys to Client")
		fmt.Println("  [0] Back to Main Menu")
		fmt.Println()

		choice := getUserInput("Select an option: ")

		switch choice {
		case "1":
			generateKeys()
		case "2":
			generateTOTPSecret()
		case "3":
			viewKeyStatus()
		case "4":
			copyKeysToClient()
		case "0":
			return
		default:
			fmt.Println(menuColorRed + "[!] Invalid option." + menuColorReset)
			pause()
		}
	}
}

func generateKeys() {
	fmt.Println("\n" + menuColorCyan + "[*] Generating Ed25519 key pair..." + menuColorReset)

	keyDir := getUserInputWithDefault("Key directory", "./keys")

	// Check if keys exist
	publicKeyPath := filepath.Join(keyDir, "spa_public.key")
	if _, err := os.Stat(publicKeyPath); err == nil {
		overwrite := getUserInput("Keys already exist. Overwrite? (y/N): ")
		if strings.ToLower(overwrite) != "y" {
			fmt.Println(menuColorYellow + "[*] Cancelled." + menuColorReset)
			pause()
			return
		}
	}

	// Run spa-keygen
	cmd := exec.Command("go", "run", "./cmd/spa-keygen", "-dir", keyDir, "-force")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		fmt.Println(menuColorRed + "[!] Failed to generate keys: " + err.Error() + menuColorReset)
	} else {
		fmt.Println(menuColorGreen + "[+] Keys generated successfully!" + menuColorReset)
	}

	pause()
}

func generateTOTPSecret() {
	fmt.Println("\n" + menuColorCyan + "[*] Generating TOTP secret..." + menuColorReset)

	keyDir := getUserInputWithDefault("Key directory", "./keys")
	secretPath := filepath.Join(keyDir, "totp_secret.txt")

	// Check if secret exists
	if _, err := os.Stat(secretPath); err == nil {
		overwrite := getUserInput("TOTP secret already exists. Overwrite? (y/N): ")
		if strings.ToLower(overwrite) != "y" {
			fmt.Println(menuColorYellow + "[*] Cancelled." + menuColorReset)
			pause()
			return
		}
	}

	// Generate secret securely using Go's crypto/rand
	generateTOTPSecretGo(secretPath)

	pause()
}

func generateTOTPSecretGo(path string) {
	// Generate 32 random bytes
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		fmt.Println(menuColorRed + "[!] Failed to generate random secret: " + err.Error() + menuColorReset)
		return
	}

	// Encode to base64
	encoded := base64.StdEncoding.EncodeToString(secret)

	// Write to file
	if err := os.WriteFile(path, []byte(encoded), 0600); err != nil {
		fmt.Println(menuColorRed + "[!] Failed to write TOTP secret: " + err.Error() + menuColorReset)
		return
	}

	fmt.Println(menuColorGreen + "[+] TOTP secret generated successfully!" + menuColorReset)
	fmt.Println(menuColorCyan + "[*] Secret saved to: " + path + menuColorReset)
}

func viewKeyStatus() {
	fmt.Println("\n" + menuColorCyan + "[*] Checking key status..." + menuColorReset)

	keyDir := getUserInputWithDefault("Key directory", "./keys")

	publicKeyPath := filepath.Join(keyDir, "spa_public.key")
	privateKeyPath := filepath.Join(keyDir, "spa_private.key")
	totpSecretPath := filepath.Join(keyDir, "totp_secret.txt")

	fmt.Println()
	fmt.Println(menuColorBold + "Key Status:" + menuColorReset)
	fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")

	checkFile("Public Key", publicKeyPath)
	checkFile("Private Key", privateKeyPath)
	checkFile("TOTP Secret", totpSecretPath)

	pause()
}

func checkFile(name, path string) {
	if info, err := os.Stat(path); err == nil {
		fmt.Printf("  %s: %s %s(%d bytes)%s\n",
			name,
			menuColorGreen+"[OK]"+menuColorReset,
			menuColorCyan,
			info.Size(),
			menuColorReset)
	} else {
		fmt.Printf("  %s: %s %s(not found)%s\n",
			name,
			menuColorRed+"[MISSING]"+menuColorReset,
			menuColorYellow,
			menuColorReset)
	}
}

func copyKeysToClient() {
	fmt.Println("\n" + menuColorCyan + "[*] Copy Keys to Client" + menuColorReset)
	fmt.Println()
	fmt.Println("To copy keys to a client machine, use one of these methods:")
	fmt.Println()
	fmt.Println(menuColorBold + "Method 1: SCP (Linux/macOS)" + menuColorReset)
	fmt.Println("  scp keys/spa_private.key user@client-ip:~/.phantom-grid/")
	fmt.Println("  scp keys/totp_secret.txt user@client-ip:~/.phantom-grid/")
	fmt.Println()
	fmt.Println(menuColorBold + "Method 2: Manual Copy" + menuColorReset)
	fmt.Println("  1. Copy keys/spa_private.key to client")
	fmt.Println("  2. Copy keys/totp_secret.txt to client")
	fmt.Println("  3. Set permissions: chmod 600 ~/.phantom-grid/*")
	fmt.Println()

	keyDir := getUserInputWithDefault("Key directory", "./keys")
	fmt.Println()
	fmt.Println(menuColorCyan + "[*] Keys location: " + keyDir + menuColorReset)

	pause()
}

func handleAgentManagement() {
	for {
		clearScreen()
		fmt.Println(menuColorBold + "\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" + menuColorReset)
		fmt.Println(menuColorBold + "                        AGENT MANAGEMENT" + menuColorReset)
		fmt.Println(menuColorBold + "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" + menuColorReset)
		fmt.Println()
		fmt.Println("  [1] Start Agent (Interactive)")
		fmt.Println("  [2] Start Agent (Background)")
		fmt.Println("  [3] Stop Agent")
		fmt.Println("  [4] View Agent Status")
		fmt.Println("  [5] Configure Agent")
		fmt.Println("  [0] Back to Main Menu")
		fmt.Println()

		choice := getUserInput("Select an option: ")

		switch choice {
		case "1":
			startAgentInteractive()
		case "2":
			startAgentBackground()
		case "3":
			stopAgent()
		case "4":
			viewAgentStatus()
		case "5":
			configureAgent()
		case "0":
			return
		default:
			fmt.Println(menuColorRed + "[!] Invalid option." + menuColorReset)
			pause()
		}
	}
}

func isRoot() bool {
	if runtime.GOOS == "windows" {
		// On Windows, check if running as administrator
		// Try to open a system device that requires admin privileges
		_, err := os.Open("\\\\.\\PHYSICALDRIVE0")
		return err == nil
	}
	// On Unix-like systems, check if UID is 0
	// Note: os.Geteuid() may not be available on all systems, but it's standard on Linux
	if runtime.GOOS == "linux" || runtime.GOOS == "darwin" || runtime.GOOS == "freebsd" {
		return os.Geteuid() == 0
	}
	// For other Unix-like systems, assume not root if we can't check
	return false
}

func startAgentInteractive() {
	fmt.Println("\n" + menuColorCyan + "[*] Starting agent interactively..." + menuColorReset)

	// Check platform
	if runtime.GOOS == "windows" {
		fmt.Println(menuColorRed + "[!] ERROR: Phantom Grid agent requires Linux with eBPF/XDP support." + menuColorReset)
		fmt.Println(menuColorYellow + "[*] eBPF/XDP is not available on Windows." + menuColorReset)
		fmt.Println(menuColorCyan + "[*] Please run the agent on a Linux system (kernel 5.4+)." + menuColorReset)
		pause()
		return
	}

	// Check if running as root
	if !isRoot() {
		fmt.Println(menuColorYellow + "[!] Warning: Agent requires root privileges for eBPF/XDP operations." + menuColorReset)
		fmt.Println(menuColorCyan + "[*] The command will be run with 'sudo'. You may be prompted for your password." + menuColorReset)
		fmt.Println()
	}

	// Get configuration
	interfaceName := getUserInputWithDefault("Network interface", "")
	spaMode := getUserInputWithDefault("SPA mode (static/dynamic/asymmetric)", "asymmetric")
	outputMode := getUserInputWithDefault("Output mode (dashboard/elk/both)", "dashboard")

	// Build command arguments
	args := []string{"run", "./cmd/agent"}
	if interfaceName != "" {
		args = append(args, "-interface", interfaceName)
	}
	args = append(args, "-spa-mode", spaMode)
	args = append(args, "-output", outputMode)

	if spaMode == "static" {
		// For static mode, ask for token
		staticToken := getUserInputWithDefault("Static token (press Enter to prompt later)", "")
		if staticToken != "" {
			args = append(args, "-spa-static-token", staticToken)
		}
	} else {
		// For dynamic modes, ask for key directory
		keyDir := getUserInputWithDefault("Key directory", "./keys")
		args = append(args, "-spa-key-dir", keyDir)
	}

	if outputMode == "elk" || outputMode == "both" {
		elkAddr := getUserInputWithDefault("Elasticsearch address", "http://localhost:9200")
		args = append(args, "-elk-address", elkAddr)
	}

	// Build command - use sudo if not root
	var cmd *exec.Cmd
	if !isRoot() {
		// Need to use sudo - preserve environment with -E flag
		sudoArgs := append([]string{"-E", "go"}, args...)
		cmd = exec.Command("sudo", sudoArgs...)
		fmt.Println()
		fmt.Println(menuColorYellow + "[*] Running with sudo: sudo go " + strings.Join(args, " ") + menuColorReset)
	} else {
		// Already root
		cmd = exec.Command("go", args...)
		fmt.Println()
		fmt.Println(menuColorYellow + "[*] Starting agent with: go " + strings.Join(args, " ") + menuColorReset)
	}

	fmt.Println(menuColorYellow + "[*] Press Ctrl+C to stop" + menuColorReset)
	fmt.Println()

	// Set up command I/O
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin

	// Run agent
	if err := cmd.Run(); err != nil {
		fmt.Println()
		fmt.Println(menuColorRed + "[!] Agent failed to start. Possible reasons:" + menuColorReset)
		if !isRoot() {
			fmt.Println(menuColorYellow + "    1. Permission denied - sudo password may be required or incorrect" + menuColorReset)
		}
		fmt.Println(menuColorYellow + "    2. eBPF not supported - requires Linux kernel 5.4+" + menuColorReset)
		fmt.Println(menuColorYellow + "    3. Interface not found - check interface name" + menuColorReset)
		fmt.Println(menuColorYellow + "    4. Missing dependencies - ensure clang, llvm, libbpf-dev are installed" + menuColorReset)
		fmt.Println()
		if !isRoot() {
			fmt.Println(menuColorCyan + "[*] Try running manually: sudo go run ./cmd/agent -interface " + interfaceName + menuColorReset)
		} else {
			fmt.Println(menuColorCyan + "[*] Try running manually: go run ./cmd/agent -interface " + interfaceName + menuColorReset)
		}
		fmt.Println()
		fmt.Println(menuColorRed + "[!] Error details: " + err.Error() + menuColorReset)
	}

	pause()
}

func startAgentBackground() {
	fmt.Println(menuColorYellow + "[!] Background mode not yet implemented." + menuColorReset)
	fmt.Println(menuColorCyan + "[*] Use systemd or screen/tmux for background execution." + menuColorReset)
	pause()
}

func stopAgent() {
	fmt.Println("\n" + menuColorCyan + "[*] Stopping agent..." + menuColorReset)

	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		cmd = exec.Command("taskkill", "/F", "/IM", "phantom-grid.exe")
	} else {
		cmd = exec.Command("pkill", "-f", "phantom-grid")
	}

	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		fmt.Println(menuColorYellow + "[*] No running agent found or failed to stop." + menuColorReset)
	} else {
		fmt.Println(menuColorGreen + "[+] Agent stopped successfully." + menuColorReset)
	}

	pause()
}

func viewAgentStatus() {
	fmt.Println("\n" + menuColorCyan + "[*] Checking agent status..." + menuColorReset)

	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		cmd = exec.Command("tasklist", "/FI", "IMAGENAME eq phantom-grid.exe")
	} else {
		cmd = exec.Command("pgrep", "-f", "phantom-grid")
	}

	output, err := cmd.Output()
	if err != nil || len(output) == 0 {
		fmt.Println(menuColorYellow + "[*] Agent is not running." + menuColorReset)
	} else {
		fmt.Println(menuColorGreen + "[+] Agent is running:" + menuColorReset)
		fmt.Println(string(output))
	}

	pause()
}

func configureAgent() {
	fmt.Println(menuColorYellow + "[!] Agent configuration editor not yet implemented." + menuColorReset)
	fmt.Println(menuColorCyan + "[*] Edit internal/config/ports.go to configure ports." + menuColorReset)
	fmt.Println(menuColorCyan + "[*] Use command-line flags to configure runtime options." + menuColorReset)
	pause()
}

func handleSPATest() {
	for {
		clearScreen()
		fmt.Println(menuColorBold + "\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" + menuColorReset)
		fmt.Println(menuColorBold + "                            SPA TESTING" + menuColorReset)
		fmt.Println(menuColorBold + "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" + menuColorReset)
		fmt.Println()
		fmt.Println("  [1] Quick Send (Auto-detect keys)")
		fmt.Println("  [2] Custom Configuration")
		fmt.Println("  [3] Static SPA (Legacy)")
		fmt.Println("  [0] Back to Main Menu")
		fmt.Println()

		choice := getUserInput("Select an option: ")

		switch choice {
		case "1":
			quickSendSPA()
		case "2":
			customSPA()
		case "3":
			staticSPA()
		case "0":
			return
		default:
			fmt.Println(menuColorRed + "[!] Invalid option." + menuColorReset)
			pause()
		}
	}
}

func quickSendSPA() {
	clearScreen()
	fmt.Println(menuColorBold + "\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" + menuColorReset)
	fmt.Println(menuColorBold + "                         QUICK SPA SEND" + menuColorReset)
	fmt.Println(menuColorBold + "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" + menuColorReset)
	fmt.Println()

	serverIP := getUserInput("Server IP address: ")
	if serverIP == "" {
		fmt.Println(menuColorRed + "[!] Server IP is required." + menuColorReset)
		pause()
		return
	}

	fmt.Println()
	fmt.Println(menuColorCyan + "[*] Auto-detecting keys..." + menuColorReset)

	// Try to find keys automatically
	keyPaths := []string{
		"./keys/spa_private.key",
		filepath.Join(os.Getenv("HOME"), ".phantom-grid", "spa_private.key"),
		filepath.Join(os.Getenv("USERPROFILE"), ".phantom-grid", "spa_private.key"), // Windows
	}

	var keyPath string
	for _, path := range keyPaths {
		if _, err := os.Stat(path); err == nil {
			keyPath = path
			fmt.Println(menuColorGreen + "[+] Found private key: " + path + menuColorReset)
			break
		}
	}

	if keyPath == "" {
		fmt.Println(menuColorRed + "[!] Private key not found in default locations:" + menuColorReset)
		for _, path := range keyPaths {
			fmt.Println(menuColorYellow + "    - " + path + menuColorReset)
		}
		fmt.Println()
		fmt.Println(menuColorCyan + "[*] Please copy keys from server or use Custom Configuration option." + menuColorReset)
		pause()
		return
	}

	// Try to find TOTP secret
	totpPaths := []string{
		"./keys/totp_secret.txt",
		filepath.Join(os.Getenv("HOME"), ".phantom-grid", "totp_secret.txt"),
		filepath.Join(os.Getenv("USERPROFILE"), ".phantom-grid", "totp_secret.txt"), // Windows
	}

	var totpPath string
	for _, path := range totpPaths {
		if _, err := os.Stat(path); err == nil {
			totpPath = path
			fmt.Println(menuColorGreen + "[+] Found TOTP secret: " + path + menuColorReset)
			break
		}
	}

	if totpPath == "" {
		fmt.Println(menuColorYellow + "[!] TOTP secret not found. Sending without TOTP (may fail if server requires it)." + menuColorReset)
	}

	fmt.Println()
	fmt.Println(menuColorCyan + "[*] Sending SPA packet to " + serverIP + "..." + menuColorReset)
	fmt.Println()

	// Build command
	args := []string{"run", "./cmd/spa-client", "-server", serverIP, "-mode", "asymmetric", "-key", keyPath}
	if totpPath != "" {
		args = append(args, "-totp", totpPath)
	}

	cmd := exec.Command("go", args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		fmt.Println()
		fmt.Println(menuColorRed + "[!] SPA send failed: " + err.Error() + menuColorReset)
		fmt.Println(menuColorYellow + "[*] Check:" + menuColorReset)
		fmt.Println(menuColorYellow + "    1. Server is running and accessible" + menuColorReset)
		fmt.Println(menuColorYellow + "    2. Keys match between client and server" + menuColorReset)
		fmt.Println(menuColorYellow + "    3. TOTP secret matches (if used)" + menuColorReset)
		fmt.Println(menuColorYellow + "    4. Firewall allows UDP port " + fmt.Sprintf("%d", config.SPAMagicPort) + menuColorReset)
	}

	pause()
}

func customSPA() {
	clearScreen()
	fmt.Println(menuColorBold + "\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" + menuColorReset)
	fmt.Println(menuColorBold + "                      CUSTOM SPA CONFIGURATION" + menuColorReset)
	fmt.Println(menuColorBold + "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" + menuColorReset)
	fmt.Println()

	serverIP := getUserInput("Server IP address: ")
	if serverIP == "" {
		fmt.Println(menuColorRed + "[!] Server IP is required." + menuColorReset)
		pause()
		return
	}

	mode := getUserInputWithDefault("SPA mode (static/dynamic/asymmetric)", "asymmetric")

	args := []string{"run", "./cmd/spa-client", "-server", serverIP, "-mode", mode}

	if mode != "static" {
		keyPath := getUserInputWithDefault("Private key path", "./keys/spa_private.key")
		args = append(args, "-key", keyPath)

		totpPath := getUserInputWithDefault("TOTP secret path (press Enter to skip)", "")
		if totpPath != "" {
			args = append(args, "-totp", totpPath)
		}
	}

	fmt.Println()
	fmt.Println(menuColorCyan + "[*] Sending SPA packet..." + menuColorReset)
	fmt.Println()

	cmd := exec.Command("go", args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		fmt.Println(menuColorRed + "[!] SPA send failed: " + err.Error() + menuColorReset)
	}

	pause()
}

func staticSPA() {
	clearScreen()
	fmt.Println(menuColorBold + "\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" + menuColorReset)
	fmt.Println(menuColorBold + "                         STATIC SPA (LEGACY)" + menuColorReset)
	fmt.Println(menuColorBold + "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" + menuColorReset)
	fmt.Println()
	fmt.Println(menuColorYellow + "[!] Warning: Static SPA is less secure. Use Dynamic Asymmetric SPA for production." + menuColorReset)
	fmt.Println()

	serverIP := getUserInput("Server IP address: ")
	if serverIP == "" {
		fmt.Println(menuColorRed + "[!] Server IP is required." + menuColorReset)
		pause()
		return
	}

	token := getUserInputWithDefault("Static token (press Enter for default)", "")

	fmt.Println()
	fmt.Println(menuColorCyan + "[*] Sending static SPA packet..." + menuColorReset)
	fmt.Println()

	args := []string{"run", "./cmd/spa-client", "-server", serverIP, "-mode", "static"}
	if token != "" {
		args = append(args, "-static-token", token)
	}

	cmd := exec.Command("go", args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		fmt.Println(menuColorRed + "[!] SPA send failed: " + err.Error() + menuColorReset)
	}

	pause()
}

func handleConfiguration() {
	for {
		clearScreen()
		fmt.Println(menuColorBold + "\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" + menuColorReset)
		fmt.Println(menuColorBold + "                          CONFIGURATION" + menuColorReset)
		fmt.Println(menuColorBold + "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" + menuColorReset)
		fmt.Println()
		fmt.Println("  [1] View Protected Ports")
		fmt.Println("  [2] View Fake Ports (Honeypot)")
		fmt.Println("  [3] Regenerate eBPF Configuration")
		fmt.Println("  [0] Back to Main Menu")
		fmt.Println()

		choice := getUserInput("Select an option: ")

		switch choice {
		case "1":
			viewProtectedPorts()
		case "2":
			viewFakePorts()
		case "3":
			regenerateEBPFConfig()
		case "0":
			return
		default:
			fmt.Println(menuColorRed + "[!] Invalid option." + menuColorReset)
			pause()
		}
	}
}

func viewProtectedPorts() {
	fmt.Println("\n" + menuColorCyan + "[*] Protected Ports (Critical Assets):" + menuColorReset)
	fmt.Println()

	ports := config.GetCriticalPorts()
	if len(ports) == 0 {
		fmt.Println(menuColorYellow + "[*] No protected ports configured." + menuColorReset)
	} else {
		for _, port := range ports {
			fmt.Printf("  Port %d: %s\n", port, getPortName(port))
		}
	}

	pause()
}

func viewFakePorts() {
	fmt.Println("\n" + menuColorCyan + "[*] Fake Ports (Honeypot - The Mirage):" + menuColorReset)
	fmt.Println()

	ports := config.GetFakePorts()
	if len(ports) == 0 {
		fmt.Println(menuColorYellow + "[*] No fake ports configured." + menuColorReset)
	} else {
		for _, port := range ports {
			fmt.Printf("  Port %d: %s\n", port, getPortName(port))
		}
	}

	pause()
}

func getPortName(port int) string {
	// Try to find in critical ports
	for _, def := range config.CriticalPortDefinitions {
		if def.Port == port {
			return def.Name
		}
	}
	// Try to find in fake ports
	for _, def := range config.FakePortDefinitions {
		if def.Port == port {
			return def.Name
		}
	}
	return "Unknown"
}

func regenerateEBPFConfig() {
	fmt.Println("\n" + menuColorCyan + "[*] Regenerating eBPF configuration..." + menuColorReset)

	cmd := exec.Command("go", "run", "./cmd/config-gen")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		fmt.Println(menuColorRed + "[!] Failed to regenerate configuration: " + err.Error() + menuColorReset)
	} else {
		fmt.Println(menuColorGreen + "[+] Configuration regenerated successfully!" + menuColorReset)
		fmt.Println(menuColorCyan + "[*] Run 'make generate' to rebuild eBPF programs." + menuColorReset)
	}

	pause()
}

func handleSystemInfo() {
	clearScreen()
	fmt.Println(menuColorBold + "\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" + menuColorReset)
	fmt.Println(menuColorBold + "                        SYSTEM INFORMATION" + menuColorReset)
	fmt.Println(menuColorBold + "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" + menuColorReset)
	fmt.Println()

	fmt.Println(menuColorCyan + "System:" + menuColorReset)
	fmt.Printf("  OS: %s\n", runtime.GOOS)
	fmt.Printf("  Architecture: %s\n", runtime.GOARCH)
	fmt.Println()

	fmt.Println(menuColorCyan + "Configuration:" + menuColorReset)
	fmt.Printf("  SPA Magic Port: %d\n", config.SPAMagicPort)
	fmt.Printf("  SSH Port: %d\n", config.SSHPort)
	fmt.Printf("  Honeypot Port: %d\n", config.HoneypotPort)
	fmt.Printf("  Protected Ports: %d\n", len(config.GetCriticalPorts()))
	fmt.Printf("  Fake Ports: %d\n", len(config.GetFakePorts()))
	fmt.Println()

	fmt.Println(menuColorCyan + "Network Interfaces:" + menuColorReset)
	listNetworkInterfaces()

	pause()
}

func listNetworkInterfaces() {
	if runtime.GOOS == "windows" {
		cmd := exec.Command("ipconfig")
		output, _ := cmd.Output()
		fmt.Println(string(output))
	} else {
		cmd := exec.Command("ip", "link", "show")
		output, _ := cmd.Output()
		fmt.Println(string(output))
	}
}

func handleDocumentation() {
	for {
		clearScreen()
		fmt.Println(menuColorBold + "\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" + menuColorReset)
		fmt.Println(menuColorBold + "                           DOCUMENTATION" + menuColorReset)
		fmt.Println(menuColorBold + "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" + menuColorReset)
		fmt.Println()
		fmt.Println("  [1] Getting Started Guide")
		fmt.Println("  [2] SPA Mechanism Explained")
		fmt.Println("  [3] Key Management Guide")
		fmt.Println("  [4] Troubleshooting Guide")
		fmt.Println("  [5] Configuration Guide")
		fmt.Println("  [0] Back to Main Menu")
		fmt.Println()

		choice := getUserInput("Select an option: ")

		docs := map[string]string{
			"1": "docs/GETTING_STARTED.md",
			"2": "docs/SPA_MECHANISM_EXPLAINED.md",
			"3": "docs/SPA_KEYS_MANAGEMENT.md",
			"4": "docs/SPA_TROUBLESHOOTING.md",
			"5": "docs/CONFIGURING_PORTS.md",
		}

		if doc, ok := docs[choice]; ok {
			viewDocumentation(doc)
		} else if choice == "0" {
			return
		} else {
			fmt.Println(menuColorRed + "[!] Invalid option." + menuColorReset)
			pause()
		}
	}
}

func viewDocumentation(file string) {
	if _, err := os.Stat(file); err != nil {
		fmt.Println(menuColorRed + "[!] Documentation file not found: " + file + menuColorReset)
		pause()
		return
	}

	// Try to open with default viewer
	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		cmd = exec.Command("notepad", file)
	} else {
		// Try different viewers
		viewers := []string{"less", "cat", "more"}
		for _, viewer := range viewers {
			if _, err := exec.LookPath(viewer); err == nil {
				cmd = exec.Command(viewer, file)
				break
			}
		}
		if cmd == nil {
			cmd = exec.Command("cat", file)
		}
	}

	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin
	cmd.Run()

	pause()
}

func getUserInput(prompt string) string {
	fmt.Print(menuColorCyan + prompt + menuColorReset)
	reader := bufio.NewReader(os.Stdin)
	input, _ := reader.ReadString('\n')
	return strings.TrimSpace(input)
}

func getUserInputWithDefault(prompt, defaultValue string) string {
	if defaultValue != "" {
		fmt.Print(menuColorCyan + prompt + " [" + defaultValue + "]: " + menuColorReset)
	} else {
		fmt.Print(menuColorCyan + prompt + ": " + menuColorReset)
	}
	reader := bufio.NewReader(os.Stdin)
	input, _ := reader.ReadString('\n')
	input = strings.TrimSpace(input)
	if input == "" {
		return defaultValue
	}
	return input
}

func pause() {
	fmt.Println()
	fmt.Print(menuColorYellow + "Press Enter to continue..." + menuColorReset)
	bufio.NewReader(os.Stdin).ReadBytes('\n')
}
