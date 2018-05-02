/* MQTT component of the Network Management Center (NMC)
 * Takes care of connection to MQTT broker
 */

package main

import (
	"encoding/json"
	"fmt"
	"github.com/eclipse/paho.mqtt.golang"
	"os"
	"os/signal"
	"syscall"
)

type SPINnode struct {
	Id       int
	Name     string
	Mac      string
	Lastseen int
	Ips      []string
	Domains  []string
}

type SPINflow struct {
	From      SPINnode
	To        SPINnode
	From_port int
	To_port   int
	Size      int
	Count     int
}

type SPINresult struct {
	Flows       []SPINflow // in case of flow data
	Timestamp   int
	Total_size  int
	Total_count int
	From        SPINnode // in case of dnsquery
	Queriednode SPINnode // in case of dnsquery
	Query       string   // in case of dnsquery
}

type SPINdata struct {
	Command  string
	Argument string
	Result   SPINresult
}

func ConnectToBroker(ip string, port string) mqtt.Client {
	// Connect to message broker, returns new Client.
	opts := mqtt.NewClientOptions().AddBroker("ws://" + ip + ":" + port)
	opts.SetClientID("spin-nms")                       // our identifier
	opts.SetAutoReconnect(true)                        // once connected, always reconnect
	opts.SetOnConnectHandler(onConnectHandler)         // when (re)connected
	opts.SetConnectionLostHandler(onDisconnectHandler) // when connection is lost
	c := mqtt.NewClient(opts)

	fmt.Println("Connecting...")
	if token := c.Connect(); token.Wait() && token.Error() != nil {
		fmt.Println("Error: ", token.Error())
	}

	return c
}

func HandleKillSignal(client mqtt.Client) {
	// Set a signal handler
	csig := make(chan os.Signal, 2)
	signal.Notify(csig, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-csig
		fmt.Println("\nDisconnecting...")
		client.Disconnect(250) // disconnect and wait 250ms for it to finish
		os.Exit(1)
	}()
}

func onConnectHandler(client mqtt.Client) {
	// fired when a connection has been established. Either the initial, or a reconnection
	fmt.Printf("Connected to server.\n")
	if token := client.Subscribe("SPIN/traffic", 0, messageHandler); token.Wait() && token.Error() != nil {
		fmt.Println("Unable to subscribe", token.Error())
		os.Exit(1)
	}
}

func onDisconnectHandler(client mqtt.Client, err error) {
	// fired when the connection was lost unexpectedly.
	// not fired on intented disconnect
	fmt.Println("Disconnected: ", err)
}

func messageHandler(client mqtt.Client, msg mqtt.Message) {
	//fmt.Printf("TOPIC: %s\n", msg.Topic())
	//fmt.Printf("MSG: %s\n", msg.Payload())

	var parsed SPINdata
	err := json.Unmarshal(msg.Payload(), &parsed)
	if err != nil {
		fmt.Println("Error while parsing", err)
		return
	}
	//fmt.Printf("MSG: %+v\n", parsed)
	if !HistoryAdd(parsed) {
		fmt.Println("messageHandler(): unable to add flow to history")
	}
}
