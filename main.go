/*
 * SPIN Network Management Center (NMC)
 * Made by SIDN Labs (sidnlabs@sidn.nl)
 */
package main

import (
	"time"
)

func main() {
	// Setup for incoming connections.

	client := ConnectToBroker("192.168.8.1", "1884")

	HandleKillSignal(client)

	for {
		time.Sleep(10 * time.Second)
	}
}
