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
	server := NewServer(messages, ServerConfig{
		BindAddress: "127.0.0.1",
		BindPort:    25,
	})
	go handleMessages(messages)
	server.Start()
	server.Drain()
}
