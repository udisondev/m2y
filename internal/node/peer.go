package node

import (
	"crypto/ecdh"
	"crypto/sha256"
	"encoding/hex"
	"sync"
)

type peerID []byte

type peer struct {
	ID         peerID
	Disconnect func()
	Send       func(Signal)
	State      PeerState
	Mutex      sync.RWMutex
}

type onboarding struct {
	Mu               sync.Mutex
	Secrets          [][]byte
	RequiresConns    int
	ConnectionProofs int
}

type PeerState int8

const (
	Disconntected PeerState = iota - 1
	Verified
	Trusted
)

func (o *onboarding) AddSecret(s []byte) bool {
	o.Mu.Lock()
	defer o.Mu.Unlock()
	if len(o.Secrets) >= 5 {
		return false
	}
	o.Secrets = append(o.Secrets, s)
	return true
}

func (p peerID) Sum256() []byte {
	hash := sha256.Sum256(p)
	return hash[:]
}

func (p peerID) Hex256() string {
	return hex.EncodeToString(p.Sum256())
}

func (p peerID) Hex() string {
	return hex.EncodeToString(p)
}

func (p peerID) PubKey() (*ecdh.PublicKey, error) {
	pubKey, err := ecdh.P256().NewPublicKey([]byte(p))
	if err != nil {
		return nil, err
	}

	return pubKey, nil
}

func ParseHex256(b []byte) string {
	return hex.EncodeToString(b)
}
