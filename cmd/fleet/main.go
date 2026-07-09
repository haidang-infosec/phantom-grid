package main

import (
	"flag"
	"fmt"
	"log"
	"os"

	"phantom-grid/internal/webdash"
)

func main() {
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Phantom Grid - Fleet Manager (Control Plane)\n\n")
		fmt.Fprintf(os.Stderr, "Usage: %s [options]\n\n", os.Args[0])
		flag.PrintDefaults()
	}

	portFlag := flag.Int("port", 9999, "Port for the Fleet Manager dashboard")
	helpFlag := flag.Bool("h", false, "Show help message")

	flag.Parse()

	if *helpFlag {
		flag.Usage()
		os.Exit(0)
	}

	log.Printf("[FLEET] Starting Phantom Grid Fleet Manager on port %d...", *portFlag)

	// In Fleet mode, we don't have local eBPF objects
	// We pass nil for phantomObjs and egressObjs.
	// We also don't use the standard logChan for local logs, we create a dummy one.
	dummyLogChan := make(chan string)

	server := webdash.NewServer(
		*portFlag,
		dummyLogChan,
		nil,
		nil,
	)

	server.Start()

	// Block forever
	select {}
}
