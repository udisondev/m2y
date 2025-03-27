package node

import (
	"bytes"
	"log"
)

func secret(n *node, msg income) {
	err := n.sendToEntrypoint(NewSignal(
		SignalTypeConnectionProof,
		msg.Signal.Payload,
	))
	if err != nil {
		return
	}
	log.Println("Secret was sent")

}

func connectionProof(n *node, msg income) {
	peerHex := msg.From.Hex256()
	n.onboardingsMu.Lock()
	defer n.onboardingsMu.Unlock()

	onboarding, ok := n.onboardings[peerHex]
	if !ok {
		return
	}

	for _, sec := range onboarding.Secrets {
		if !bytes.Equal(sec, msg.Signal.Payload) {
			continue
		}

		log.Println("Receved secret from:", peerHex)
		onboarding.ConnectionProofs++

		if onboarding.RequiresConns == onboarding.ConnectionProofs {
			n.trust(peerHex)
			log.Println(peerHex, "are trusted yet!")
			delete(n.onboardings, peerHex)
		}
		return
	}

}
