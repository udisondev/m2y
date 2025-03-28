package node

import (
	"log"
)

var handlers = map[SignalType]func(*Node, income){
	SignalTypeNeedPeerInvite:   needInvite,
	SignalTypePeerInvite:       invite,
	SignalTypePeerOffer:        offer,
	SignalTypePeerAnswer:       answer,
	SignalTypeConnectionSecret: secret,
	SignalTypeConnectionProof:  connectionProof,
	SignalTypeChatInvite:       chatInvite,
	SignalTypeChatOffer:        chatOffer,
	SignalTypeChatAnswer:       chatAnswer,
}

func (n *Node) dispatch(msg income) {
	h, ok := handlers[msg.Signal.Type]
	if !ok {
		log.Println("Has no handler for:", msg.Signal.Type)
		return
	}
	h(n, msg)
}
