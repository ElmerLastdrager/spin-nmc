/*
 * Anomaly detection for SPIN-NMC
 * Made by SIDN Labs (sidnlabs@sidn.nl)
 */

/*
 * TODO:
 * - store state for later re-use?
 */

package main

import "fmt"

var chResolve chan SubDNS
var chNewTraffic chan SubFlow

// Initialise anomaly detection
func InitAnomaly() {
	chResolve = SubscribeResolve()
	go printResolved(chResolve)
	chNewTraffic = SubscribeNewTraffic()
	go printNewTraffic(chNewTraffic)
}

func printResolved(ch chan SubDNS) {
	for {
		req, cont := <-ch
		if !cont { // channel is closed
			break
		}
		fmt.Println("Anomaly: device ", req.Deviceid, " DNS request = ", req.Request)
	}
}

func printNewTraffic(ch chan SubFlow) {
	for {
		flowinfo, cont := <-ch
		if !cont { // channel is closed
			break
		}
		fmt.Print("Anomaly: New Flow from ", flowinfo.Deviceid, " to device ", flowinfo.NewFlow.NodeId)
		for _, ip := range flowinfo.NewFlow.RemoteIps {
			fmt.Print(" ", ip.String())
		}
		fmt.Println(" on port", flowinfo.NewFlow.RemotePort)
	}
}
