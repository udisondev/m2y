package node

import (
	"bytes"
	"crypto/sha256"
	"io"
)

type signal []byte

type (
	sigtype uint8
	invite  []byte
	offer   []byte
	answer  []byte
)

const (
	stUnknown    sigtype = 0x00
	stNeedInvite         = 0x01
	stInvite             = 0x02
	stOffer              = 0x03
	stAnswer             = 0x04
	stConnSecret         = 0x05
	stConnProof          = 0x06
	stTrusted            = 0x07
	stDisconnect         = 0xFF
)

const (
	typeEnd     = 1
	nonceEnd    = typeEnd + 12
	receiverEnd = nonceEnd + 65
	senderEnd   = receiverEnd + 65
)

const (
	fullRecSendLength  = 65
	shortRecSendLength = 32
)

var reminder = make([]byte, fullRecSendLength-shortRecSendLength)

func NewSignal(
	t sigtype,
	payload []byte,
	receiver []byte,
	sender []byte,
	w io.Writer,
) {
	w.Write([]byte{byte(t)})
	w.Write(receiver)
	if len(receiver) < fullRecSendLength {
		w.Write(reminder)
	}
	w.Write(sender)
	if len(sender) < fullRecSendLength {
		w.Write(reminder)
	}
	w.Write(payload)
}

func (s signal) stype() sigtype {
	switch s[0] {
	case 0xFF:
		return stDisconnect
	case 0x00:
		return stInvite
	default:
		return stUnknown
	}
}

func (s signal) nonce() []byte {
	return s[typeEnd:nonceEnd]
}

func (s signal) receiver() []byte {
	return s[nonceEnd:receiverEnd]
}

func (s signal) sender() []byte {
	return s[receiverEnd:senderEnd]
}

func (s signal) payload() []byte {
	return s[senderEnd:]
}

func (s signal) invite() invite {
	if s.stype() != stInvite {
		return nil
	}
	return invite(s.payload())
}

func (s signal) offer() offer {
	if s.stype() != stOffer {
		return nil
	}
	return offer(s.payload())
}

func (s signal) answer() answer {
	if s.stype() != stAnswer {
		return nil
	}
	return answer(s.payload())
}

func (s signal) forMe(b []byte) bool {
	switch s.stype() {
	case stNeedInvite, stInvite:
		return bytes.Equal(s.receiver(), b)
	default:
		sum := sha256.Sum256(b)
		return bytes.Equal(s.receiver()[:shortRecSendLength], sum[:])
	}
}
