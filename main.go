package main

import (
	"fmt"
)

func handleMessages(in <-chan Message) {
	for {
		msg := <-in
		fmt.Println("Got message\n", msg, "\n")
	}
}

func main() {
	messages := make(chan Message)
	server := NewServer(messages, SMTPConfig{
		Ip4address:      "127.0.0.1",
		Ip4port:         25,
		Domain:          "local",
		AllowedHosts:    "localhost",
		TrustedHosts:    "127.0.0.1",
		MaxRecipients:   100,
		MaxIdleSeconds:  300,
		MaxClients:      500,
		MaxMessageBytes: 20480000,
		PubKey:          "",
		PrvKey:          "",
		Debug:           false,
		DebugPath:       "",
	})
	go handleMessages(messages)
	server.Start()
	server.Drain()
}
