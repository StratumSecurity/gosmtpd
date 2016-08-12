package main

import (
	"fmt"
	"github.com/StratumSecurity/gosmtpd"
	"net"
)

func handleMessages(in <-chan smtpd.Message) {
	for {
		msg := <-in
		fmt.Println("Got message\n", msg, "\n")
	}
}

func main() {
	messages := make(chan smtpd.Message)
	server := smtpd.NewServer(messages, SMTPConfig{
		Ip4address:      net.ParseIP("127.0.0.1"),
		Ip4port:         25,
		Domain:          "smtpd.local",
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
		SpamRegex:       "",
	})
	server.Start()
	server.Drain()
}
