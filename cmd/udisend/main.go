package main

import (
	"log"
	"m2y/internal/node"
	"os"
	"runtime"
	"strings"
)

func main() {
	args := os.Args
	var (
		addr      string
		connectTo string
	)

	for _, a := range args[1:] {
		log.Printf("main: receive %s attribute", a)
		if strings.HasPrefix(a, "addr=") {
			addr = strings.Split(a, "=")[1]
		}
		if strings.HasPrefix(a, "conn=") {
			connectTo = strings.Split(a, "=")[1]
		}
	}

	n, err := node.New(addr, 10)
	if err != nil {
		log.Fatalf("Run node: %v", err)
		return
	}

	go func() {
		n.Run(runtime.NumCPU())
	}()

	if connectTo != "" {
		err := n.Connect(connectTo)
		if err != nil {
			log.Printf("Error connect to entrypoint=%s: %v", connectTo, err)
			return
		}
	}

	select {}
}
