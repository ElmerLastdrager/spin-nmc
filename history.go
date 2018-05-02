/*
 * History service for SPIN-NMC
 * Made by SIDN Labs (sidnlabs@sidn.nl)
 */

/*
 * The SPIN device (agent) may restart and use different SPIN identifiers for the same device.
 * We have to account for that.
 */

/*
 * TODO
 * - Option to subscribe to history (e.g. anomaly detection). Subscribe on new flow, existing flow, dns lookup
 */

package main

import (
	"fmt"
	"net"
	"sync"
	"time"
)

var History = struct {
	sync.RWMutex
	m           HistoryDB
	initialised bool
}{m: HistoryDB{}, initialised: false}

type HistoryDB struct {
	Devices map[int]Device // map that lists all devices
}

// Flow represents an aggregated type of flow for a single device.
// This means multiple flows to the same ip/port combination are considered one.
type Flow struct {
	RemoteIps       []net.IP  // ip addresses
	NodeId          int       // SPIN Identifier for this node
	BytesReceived   int       // Number of bytes received by the local device
	BytesSent       int       // Number of bytes sent by the local device to the remote one
	PacketsReceived int       // Number of packets received
	PacketsSent     int       // Number of packets sent
	RemotePort      int       // Port of remote server
	FirstActivity   time.Time // First time that activity was logged
	LastActivity    time.Time // Last activity of this flow
}

type Device struct {
	Mac       net.HardwareAddr    // Mac address of this device.
	SpinId    int                 // SPIN node identifier, used for quick verification of MAC. And internal references.
	Lastseen  time.Time           // Timestamp of last moment the device sent or received traffic
	Flows     []Flow              // An array of flows for this device
	Resolved  map[string][]net.IP // Resolved domains for this device. The key is the DNS request (domain).
	Addresses []net.IP            // local addresses at which this device is known
}

func InitHistory(load bool, fp string) {
	// Initialize history service
	// if load: tries to reload from disk
	if load {
		fmt.Println("InitHistory(): load not implemented")
	}
	History.Lock() // obtain write-lock
	defer History.Unlock()

	if History.m.Devices == nil {
		History.m.Devices = make(map[int]Device)
	}
	History.initialised = true
}

// Adds a flow or dnsquery to the history file
func HistoryAdd(msg SPINdata) bool {
	History.RLock()
	initialised := History.initialised
	History.RUnlock()

	if !initialised {
		// If the History file was not initialised yet, do so now
		InitHistory(false, "")
	}

	switch msg.Command {
	case "traffic":
		// do this
		//fmt.Println("Flow found", msg.Result.Flows[0].From.Id, "to", msg.Result.Flows[0].To.Id)

		History.Lock() // obtain write-lock
		defer History.Unlock()

		// Start parsing all flows
		for _, flow := range msg.Result.Flows {
			// flow
			var local, remote SPINnode
			var remoteport int

			if len(flow.From.Mac) > 0 {
				local, remote, remoteport = flow.From, flow.To, flow.To_port
			} else if len(flow.To.Mac) > 0 {
				local, remote, remoteport = flow.To, flow.From, flow.From_port
			} else {
				fmt.Println("HistoryAdd(): Unable to process flow, cannot find local device.")
				break
			}

			// Now, process flow
			deviceid := local.Id
			dev := getDevice(deviceid)

			// Compute relevant variables from flow
			ips := []net.IP{}
			for _, v := range remote.Ips {
				ips = append(ips, net.ParseIP(v))
			}

			byReceived, bySent, packReceived, packSent := 0, 0, 0, 0
			if local.Id == flow.From.Id {
				byReceived, bySent, packReceived, packSent = 0, flow.Size, 0, flow.Count
			} else {
				byReceived, bySent, packReceived, packSent = flow.Size, 0, flow.Count, 0
			}

			// TODO debug all vars

			idx, histflow := findFlow(dev.Flows, remote.Id, remoteport)

			// FIXME DEBUG
			fmt.Println("Flow: ", idx, deviceid, remote.Id, remoteport, byReceived, bySent, packReceived, packSent, time.Unix(int64(msg.Result.Timestamp), 0))

			if idx < 0 {
				// create new
				histflow = Flow{RemoteIps: ips, NodeId: remote.Id, RemotePort: remoteport, BytesReceived: byReceived,
					BytesSent: bySent, PacketsReceived: packReceived, PacketsSent: packSent,
					FirstActivity: time.Unix(int64(msg.Result.Timestamp), 0),
					LastActivity:  time.Unix(int64(msg.Result.Timestamp), 0)}
				dev.Flows = append(dev.Flows, histflow)
			} else {
				// update
				histflow.RemoteIps = mergeIP(histflow.RemoteIps, ips)
				histflow.BytesReceived += byReceived
				histflow.BytesSent += bySent
				histflow.PacketsReceived += packReceived
				histflow.PacketsSent += packSent
				histflow.LastActivity = time.Unix(int64(msg.Result.Timestamp), 0)
				dev.Flows[idx] = histflow
			}

			// Store results
			History.m.Devices[deviceid] = dev
		}

		// first, we need to determine which of the nodes is the local device

		// Probably, it had DNS traffic before, so if no MAC address is set, do so now
		// But, if a MAC is set, MAC takes priority over spin identifier

		return true
	case "dnsquery":
		// do that
		fmt.Println("DNS query for", msg.Result.Query)

		deviceid := msg.Result.From.Id

		History.Lock() // obtain write-lock
		defer History.Unlock()

		dev := getDevice(deviceid)

		dnsq, exists := dev.Resolved[msg.Result.Query]
		// check if dns query exists, if not: make new one
		if !exists {
			dnsq = []net.IP{}
		}

		// merge sets of resolved IPs
		rip := []net.IP{}
		for _, i := range msg.Result.Queriednode.Ips {
			rip = append(rip, net.ParseIP(i))
		}
		dnsq = mergeIP(dnsq, rip)

		// and merge dnsq back to dns
		dev.Resolved[msg.Result.Query] = dnsq

		// merge set of node ips
		rip = []net.IP{}
		for _, i := range msg.Result.From.Ips {
			rip = append(rip, net.ParseIP(i))
		}
		dev.Addresses = mergeIP(dev.Addresses, rip)

		// and update the lastseen field
		dev.Lastseen = time.Unix(int64(msg.Result.From.Lastseen), 0)

		// dev now contains all updates
		// put results back to History
		History.m.Devices[deviceid] = dev

		return true
	}
	return false
}

// Requires (at least) a Read lock on the History
// Returns device information, or returns new one
func getDevice(deviceid int) Device {
	dev, exists := History.m.Devices[deviceid]
	// If not yet there, make an empty one
	if !exists {
		dev = Device{Mac: nil, SpinId: deviceid, Lastseen: time.Now(),
			Flows: []Flow{}, Resolved: make(map[string][]net.IP),
			Addresses: []net.IP{}}
	}
	return dev
}

// Merges two lists of ip addresses
func mergeIP(ip1 []net.IP, ip2 []net.IP) []net.IP {
	for _, ip := range ip2 {
		found := false
		for _, comp := range ip1 {
			if comp.Equal(ip) {
				found = true
				break
			}
		}
		if !found {
			ip1 = append(ip1, ip)
		}
	}
	return ip1
}

// Requires at least a read lock on History
// Returns index and the corresponding Flow, or index = -1 if no flows were found
// The index is only valid until you release the read lock
func findFlow(flows []Flow, id int, port int) (int, Flow) {
	for idx, flow := range flows {
		if flow.NodeId == id && flow.RemotePort == port {
			return idx, flow
		}
	}
	return -1, Flow{}
}
