package main

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"log"
	"m2y/internal/node"
	"os"
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

	privateECDH, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
	}

	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
	}
	n := node.Node{
		Addr:        addr,
		ID:          privateECDH.PublicKey().Bytes(),
		Peers:       map[string]*node.Peer{},
		Inbox:       make(chan node.Income),
		WaitOffers:  map[string]node.Offerer{},
		WaitAnswers: map[string]node.Answerer{},
		Onboardings: map[string]*node.Onboarding{},
		EDPublic:    public,
		EDPrivate:   private,
		ECDHPublic:  privateECDH.PublicKey(),
		ECDHPrivate: privateECDH,
	}

	log.Printf("Addr=%s", addr)
	if addr != "" {
		log.Printf("Addr is not nil")
		go func() {
			n.Start()
		}()
	}

	go func() {
		n.Run(1)
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
