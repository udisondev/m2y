package node

import "time"

const (
	outboxSize            = 256
	pingPeriod            = time.Second * 7
	pongWaitTime          = time.Second * 11
	readBufferSize        = 1024
	writeBufferSize       = 1024
	ecdhPubKeyLength      = 65
	challengeSize         = 32
	inboxBufSizePerPeer   = 10
	reqConnsCount         = 5
	runCloseWait          = time.Millisecond * 500
	aesKeySize            = 32
	maxPeersCount         = reqConnsCount * 2
	signLength            = 32
	connectionProofLength = 12
	bucketsCount          = 10
	bucketCapacity        = 10000
)
