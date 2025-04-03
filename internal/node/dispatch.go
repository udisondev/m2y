package node

import (
	"bytes"
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

func (d *dispatcher) dispatch(in *bytes.Buffer, out *bytes.Buffer) {
	s := signal(in.Bytes())
	if !s.forMe(d.ecdh.PublicKey().Bytes()) {
		out.WriteByte(broadcast)
		out.Write(in.Bytes())
		return
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
	default:
		return
	}
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
