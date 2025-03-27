package node

import (
	"log"
)

var handlers = map[SignalType]func(*node, income){
	SignalTypeNeedPeerInvite:   needInvite,
	SignalTypePeerInvite:       invite,
	SignalTypePeerOffer:        offer,
	SignalTypePeerAnswer:       answer,
	SignalTypeConnectionSecret: secret,
	SignalTypeConnectionProof:  connectionProof,
}

func (n *node) dispatch(msg income) {
	h, ok := handlers[msg.Signal.Type]
	if !ok {
		log.Println("Has no handler for:", msg.Signal.Type)
		return
	}
	h(n, msg)
}
