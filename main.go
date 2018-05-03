/*
 * SPIN Network Management Center (NMC)
 * Made by SIDN Labs (sidnlabs@sidn.nl)
 */
package main

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"
)

func main() {
	InitHistory(false, "") // initialize history service

	// Start modules
	InitAnomaly() // Anomaly detection

	// Connect to MQTT Broker of valibox
	ConnectToBroker("valibox.", "1884")
	HandleKillSignal()

	for {
		time.Sleep(30 * time.Second)
		// History.RLock()
		// fmt.Printf("History: %+v\n", History)
		// History.RUnlock()
	}
}

// Handle kill signals for all modules
func HandleKillSignal() {
	// Set a signal handler
	csig := make(chan os.Signal, 2)
	signal.Notify(csig, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-csig
		fmt.Println("\nShutting down...")
		KillBroker()
		KillHistory()
		os.Exit(1)
	}()
}
