package node

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"sync"
)

type dispatcher struct {
	mu          sync.Mutex
	ecdh        *ecdh.PrivateKey
	privateSign ed25519.PrivateKey
	publicSign  ed25519.PublicKey
}

func (d *dispatcher) dispatch(b []byte) (byte, []byte) {
	s := signal(b)
	if !s.forMe(d.ecdh.PublicKey().Bytes()) {
		return broadcast, b
	}

	switch s.stype() {
	case stNeedInvite:
		d.handleNeedInvite(s)
	case stInvite:
		d.handleInvite(s)
	case stOffer:
		d.handleOffer(s)
	case stAnswer:
		d.handleAnswer(s)
	case stConnSecret:
		d.handleConnSecret(s)
	case stConnProof:
		d.handleConnProof(s)
	case stTrusted:
		d.handleTrusted(s)
	}

	return disconnect, nil
}

func (d *dispatcher) handleNeedInvite(s signal) {

}

func (d *dispatcher) handleInvite(s signal) {

}

func (d *dispatcher) handleOffer(s signal) {

}

func (d *dispatcher) handleAnswer(s signal) {

}

func (d *dispatcher) handleConnSecret(s signal) {

}

func (d *dispatcher) handleConnProof(s signal) {

}

func (d *dispatcher) handleTrusted(s signal) {

}
