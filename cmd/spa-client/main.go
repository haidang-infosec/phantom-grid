package main

import (
	"embed"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"

	"phantom-grid/internal/config"
	"phantom-grid/pkg/spa"
)

//go:embed ui/*
var uiFS embed.FS

type SendRequest struct {
	Server      string `json:"server"`
	Mode        string `json:"mode"`
	KeyPath     string `json:"keyPath"`
	TotpPath    string `json:"totpPath"`
	StaticToken string `json:"staticToken"`
	ClientIP    string `json:"clientIp"`
}

func main() {
	// Custom usage function
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "SPA Client - Single Packet Authorization Client\n\n")
		fmt.Fprintf(os.Stderr, "Usage: %s [options]\n\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "Options:\n")
		flag.PrintDefaults()
	}

	// Parse command line arguments
	uiFlag := flag.Bool("ui", false, "Start the Web UI dashboard")
	uiPortFlag := flag.Int("ui-port", 9090, "Port for the Web UI (default: 9090)")
	
	serverIP := flag.String("server", "", "Server IP address")
	mode := flag.String("mode", "static", "SPA mode: 'static', 'dynamic', or 'asymmetric'")
	keyPath := flag.String("key", "", "Path to private key file")
	totpSecretPath := flag.String("totp", "", "Path to TOTP secret file")
	staticTokenFlag := flag.String("static-token", "", "Static SPA token")
	clientIPFlag := flag.String("client-ip", "", "Your IP address to bind to the SPA packet (auto-detected if empty)")
	helpFlag := flag.Bool("h", false, "Show help message")
	helpFlag2 := flag.Bool("help", false, "Show help message")
	
	flag.Parse()

	if *helpFlag || *helpFlag2 {
		flag.Usage()
		os.Exit(0)
	}

	if *uiFlag {
		startUIServer(*uiPortFlag)
		return
	}

	// Validate server IP for CLI mode
	if *serverIP == "" {
		fmt.Fprintf(os.Stderr, "Error: -server is required in CLI mode. Or use --ui for the graphical interface.\n")
		flag.Usage()
		os.Exit(1)
	}

	err := processSPARequest(*serverIP, *mode, *keyPath, *totpSecretPath, *staticTokenFlag, *clientIPFlag)
	if err != nil {
		fmt.Printf("[!] Error: %v\n", err)
		os.Exit(1)
	}
}

func startUIServer(port int) {
	mux := http.NewServeMux()

	// Serve embedded UI files
	fs := http.FileServer(http.FS(uiFS))
	mux.Handle("/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" || r.URL.Path == "/index.html" {
			r.URL.Path = "/ui/index.html"
		} else {
			r.URL.Path = "/ui" + r.URL.Path
		}
		fs.ServeHTTP(w, r)
	}))

	// Handle API requests
	mux.HandleFunc("/api/send", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		var req SendRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		err := processSPARequest(req.Server, req.Mode, req.KeyPath, req.TotpPath, req.StaticToken, req.ClientIP)
		
		if err != nil {
			json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
			return
		}

		json.NewEncoder(w).Encode(map[string]string{
			"message": "SPA Magic Packet Sent successfully!",
			"details": fmt.Sprintf("Target: %s:%d", req.Server, config.SPAMagicPort),
		})
	})

	addr := fmt.Sprintf(":%d", port)
	url := fmt.Sprintf("http://localhost%s", addr)
	fmt.Printf("[+] Starting Premium SPA Web Client on %s\n", url)
	
	// Automatically open browser
	go openBrowser(url)

	log.Fatal(http.ListenAndServe(addr, mux))
}

func processSPARequest(serverIP, modeStr, keyPath, totpPath, staticToken, clientIPStr string) error {
	// Handle static mode
	if modeStr == "static" {
		token := staticToken
		if token == "" {
			token = config.SPASecretToken
		}

		client := spa.NewClientWithToken(serverIP, token)
		fmt.Printf("[*] Sending Static SPA Magic Packet to %s...\n", serverIP)
		return client.SendMagicPacket()
	}

	// Handle dynamic modes
	spaConfig := config.DefaultDynamicSPAConfig()

	switch modeStr {
	case "dynamic":
		spaConfig.Mode = config.SPAModeDynamic
	case "asymmetric":
		spaConfig.Mode = config.SPAModeAsymmetric
	default:
		return fmt.Errorf("invalid mode: %s", modeStr)
	}

	// Load private key
	if spaConfig.Mode == config.SPAModeAsymmetric {
		if keyPath == "" {
			defaultPaths := []string{
				"./keys/spa_private.key",
				filepath.Join(os.Getenv("HOME"), ".phantom-grid", "spa_private.key"),
				filepath.Join(os.Getenv("USERPROFILE"), ".phantom-grid", "spa_private.key"),
			}
			for _, path := range defaultPaths {
				if _, err := os.Stat(path); err == nil {
					keyPath = path
					break
				}
			}
		}

		if keyPath == "" {
			return fmt.Errorf("private key required for asymmetric mode")
		}

		_, privateKey, err := config.LoadKeysFromFile("", keyPath)
		if err != nil {
			return fmt.Errorf("failed to load private key: %v", err)
		}
		spaConfig.PrivateKey = privateKey
	}

	// Load TOTP
	if totpPath == "" {
		defaultTotpPaths := []string{
			"./keys/totp_secret.txt",
			filepath.Join(os.Getenv("HOME"), ".phantom-grid", "totp_secret.txt"),
			filepath.Join(os.Getenv("USERPROFILE"), ".phantom-grid", "totp_secret.txt"),
		}
		for _, path := range defaultTotpPaths {
			if _, err := os.Stat(path); err == nil {
				totpPath = path
				break
			}
		}
	}

	if totpPath != "" {
		totpSecret, err := os.ReadFile(totpPath)
		if err == nil {
			if len(totpSecret) > 0 && totpSecret[len(totpSecret)-1] == '\n' {
				totpSecret = totpSecret[:len(totpSecret)-1]
			}
			spaConfig.TOTPSecret = totpSecret
		}
	}

	var clientIP net.IP
	if clientIPStr != "" {
		clientIP = net.ParseIP(clientIPStr)
		if clientIP == nil {
			return fmt.Errorf("invalid client IP format")
		}
	} else {
		// Auto-detect local IP used to reach server
		conn, err := net.Dial("udp", net.JoinHostPort(serverIP, "80"))
		if err == nil {
			localAddr := conn.LocalAddr().(*net.UDPAddr)
			clientIP = localAddr.IP
			conn.Close()
		} else {
			clientIP = net.ParseIP("127.0.0.1")
		}
	}

	client, err := spa.NewDynamicClient(serverIP, spaConfig, clientIP)
	if err != nil {
		return fmt.Errorf("failed to create client: %v", err)
	}

	fmt.Printf("[*] Sending %s SPA packet to %s (Bound to IP: %s)...\n", modeStr, serverIP, clientIP.String())
	return client.SendMagicPacket()
}

func openBrowser(url string) {
	var err error
	switch runtime.GOOS {
	case "linux":
		err = exec.Command("xdg-open", url).Start()
	case "windows":
		err = exec.Command("rundll32", "url.dll,FileProtocolHandler", url).Start()
	case "darwin":
		err = exec.Command("open", url).Start()
	default:
		err = fmt.Errorf("unsupported platform")
	}
	if err != nil {
		fmt.Printf("Please open %s in your browser\n", url)
	}
}
