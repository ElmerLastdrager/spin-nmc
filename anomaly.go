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
		fmt.Println("AD: device ", req.Deviceid, " DNS request = ", req.Request)
	}
}

func printNewTraffic(ch chan SubFlow) {
	for {
		flowinfo, cont := <-ch
		if !cont { // channel is closed
			break
		}
		fmt.Print("AD: New Flow from ", flowinfo.Deviceid, " to device ", flowinfo.NewFlow.NodeId)
		hostnames := IPToName(flowinfo.Deviceid, flowinfo.NewFlow.RemoteIps)
		if len(hostnames) == 0 {
			for _, ip := range flowinfo.NewFlow.RemoteIps {
				hostnames = append(hostnames, ip.String())
			}
		}
		for _, host := range hostnames {
			fmt.Print(" ", host)
		}
		fmt.Println(" on port", flowinfo.NewFlow.RemotePort)
	}
}
