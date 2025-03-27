package node

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"fmt"
)

type Signal struct {
	Type       SignalType
	Nonce      []byte
	Receipient []byte
	Sender     []byte
	Payload    []byte
}

type SignalType uint8

const (
	SignalTypeNeedPeerInvite   SignalType = 0x01
	SignalTypePeerInvite                  = 0x02
	SignalTypePeerOffer                   = 0x03
	SignalTypePeerAnswer                  = 0x04
	SignalTypeConnectionSecret            = 0x05
	SignalTypeConnectionProof             = 0x06
)

type Income struct {
	From   PeerID
	Signal Signal
}

func (i Income) RecepientHex256() string {
	return ParseHex256(i.Signal.Receipient)
}

func (i Income) IsForMe(ID PeerID) bool {
	myHash := ID.Sum256()
	return bytes.Equal(myHash[:], i.Signal.Receipient[:])
}

type SignalOpt func(Signal) Signal

func WithRecepient(r []byte) SignalOpt {
	return func(s Signal) Signal {
		s.Receipient = r
		return s
	}
}
func WithSender(s []byte) SignalOpt {
	return func(sig Signal) Signal {
		sig.Sender = s
		return sig
	}
}

func NewSignal(sigType SignalType, payload []byte, opts ...SignalOpt) Signal {
	nonce := make([]byte, 12)
	rand.Read(nonce)
	s := Signal{
		Type:    sigType,
		Nonce:   nonce,
		Payload: payload,
	}

	for _, opt := range opts {
		s = opt(s)
	}

	return s
}

func (s Signal) MarshalBinary() ([]byte, error) {
	totalLen := 1 + len(s.Payload) + len(s.Nonce) + len(s.Receipient) + len(s.Sender)

	data := make([]byte, totalLen)
	pos := 0

	data[0] = byte(s.Type)
	pos++

	copy(data[pos:], s.Nonce)
	pos += len(s.Nonce)

	if len(s.Receipient) > 0 {
		copy(data[pos:], s.Receipient)
		pos += len(s.Receipient)
	}
	if len(s.Sender) > 0 {
		copy(data[pos:], s.Sender)
		pos += len(s.Sender)
	}

	copy(data[pos:], s.Payload)

	return data, nil
}

func (s Signal) NonceHex() string {
	return hex.EncodeToString(s.Nonce)
}

func (s *Signal) UnmarshalBinary(data []byte) error {
	if len(data) < 1 {
		return fmt.Errorf("data too short: expected at least 1 byte, got %d", len(data))
	}

	s.Type = SignalType(data[0])

	rest := data[1:]

	s.Nonce = rest[:12]
	rest = rest[12:]

	if s.Type.HasRecipient() {
		s.Receipient = []byte(rest[:32])
		rest = rest[32:]
	}

	if s.Type.HasSender() {
		s.Sender = []byte(rest[:32])
		rest = rest[32:]
	}

	s.Payload = rest

	return nil
}

func (t SignalType) HasRecipient() bool {
	switch t {
	case SignalTypeConnectionProof, SignalTypeConnectionSecret:
		return false
	default:
		return true
	}
}

func (t SignalType) HasSender() bool {
	switch t {
	case SignalTypePeerOffer, SignalTypePeerAnswer:
		return true
	default:
		return false
	}
}
