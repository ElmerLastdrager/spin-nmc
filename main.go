/*
 * SPIN Network Management Center (NMC)
 * Made by SIDN Labs (sidnlabs@sidn.nl)
 */
package main

import (
	"fmt"
	"time"
)

func main() {
	InitHistory(false, "") // initialize history service

	client := ConnectToBroker("192.168.8.1", "1884")

	HandleKillSignal(client)

	for {
		time.Sleep(30 * time.Second)
		History.RLock()
		fmt.Printf("History: %+v\n", History)
		History.RUnlock()
	}
}
