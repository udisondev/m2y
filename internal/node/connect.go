package node

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/gorilla/websocket"
)

func (n *Node) Connect(peerAddr string) error {
	conn, _, err := websocket.DefaultDialer.Dial("ws://"+peerAddr+"/ws", nil)
	if err != nil {
		return err
	}

	var pubKey *ecdh.PublicKey
	var peerIDBytes []byte

	peerIDResp := make(chan []byte)
	defer close(peerIDResp)

	go func() {
		_, data, err := conn.ReadMessage()
		if err != nil {
			return
		}
		if len(data) != 65 {
			return
		}
		peerIDResp <- data
	}()

	select {
	case <-time.After(time.Second):
		return fmt.Errorf("entrypoint peerID not received!")
	case peerID, ok := <-peerIDResp:
		if !ok {
			return nil
		}
		pubKey, err = ecdh.P256().NewPublicKey(peerID)
		if err != nil {
			return fmt.Errorf("error generate entrypoint public key: %w", err)
		}
		peerIDBytes = peerID
	}

	err = conn.WriteMessage(websocket.BinaryMessage, n.ecdhPublic.Bytes())
	if err != nil {
		return fmt.Errorf("conn.WriteMessage: %w", err)
	}

	challenge := make(chan []byte)
	defer close(challenge)

	go func() {
		_, data, err := conn.ReadMessage()
		if err != nil {
			return
		}
		challenge <- data
	}()

	select {
	case <-time.After(time.Second):
		return fmt.Errorf("challenge not received!")
	case data, ok := <-challenge:
		if !ok {
			return errors.New("challenge channel closed!")
		}
		decrypted, err := n.decryptChallenge(data, pubKey)
		if err != nil {
			return fmt.Errorf("dectypt challenge: %w", err)
		}
		conn.WriteMessage(websocket.BinaryMessage, decrypted)
	}

	peerID := peerID(peerIDBytes)
	n.entrypointID = peerID

	inbox := make(chan []byte)
	outbox := n.addConn(pubKey, inbox, true)
	tcpInteraction(inbox, outbox, conn)

	return nil
}

func tcpInteraction(inbox chan<- []byte, outbox <-chan []byte, conn *websocket.Conn) {
	pingCh := make(chan struct{})
	pongCh := make(chan struct{})
	isDead := make(chan struct{})

	outbox = func(ch <-chan []byte) <-chan []byte {
		out := make(chan []byte, outboxSize)

		go func() {
			defer close(out)
			defer conn.Close()

			pingTicker := time.NewTicker(pingPeriod)
			for {
				select {
				case <-pingCh:
					out <- pongSignal
				case <-pingTicker.C:
					out <- pingSignal
				case data, work := <-ch:
					if !work {
						return
					}
					out <- data
				case <-isDead:
					return
				}
			}
		}()

		return out
	}(outbox)

	go func() {
		for data := range outbox {
			conn.WriteMessage(websocket.BinaryMessage, data)
		}
	}()

	go func() {
		defer close(inbox)

		for {
			_, data, err := conn.ReadMessage()
			if err != nil {
				return
			}

			if bytes.Equal(data, pingSignal) {
				log.Println("Ping")
				pingCh <- struct{}{}
				continue
			}

			if bytes.Equal(data, pongSignal) {
				log.Println("Pong")
				pongCh <- struct{}{}
				continue
			}

			if len(data) < 1 {
				return
			}
			inbox <- data
		}
	}()

	go func() {
		defer close(isDead)

		for {
			select {
			case <-pongCh:
				continue
			case <-time.After(pongWaitTime):
				return
			}
		}
	}()
}

func (n *Node) handleConnection(w http.ResponseWriter, r *http.Request) {
	upgrader := websocket.Upgrader{
		ReadBufferSize:  readBufferSize,
		WriteBufferSize: writeBufferSize,
		CheckOrigin:     func(r *http.Request) bool { return true },
	}

	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	defer func() {
		if err == nil {
			return
		}
		conn.Close()
	}()

	var pubKey *ecdh.PublicKey
	var peerIDBytes []byte

	peerIDResp := make(chan []byte)
	defer close(peerIDResp)

	go func() {
		_, data, err := conn.ReadMessage()
		if err != nil {
			return
		}
		if len(data) != ecdhPubKeyLength {
			return
		}
		peerIDResp <- data
	}()

	err = conn.WriteMessage(websocket.BinaryMessage, n.ecdhPublic.Bytes())
	if err != nil {
		return
	}

	select {
	case <-time.After(time.Second):
		return
	case peerID, ok := <-peerIDResp:
		if !ok {
			return
		}
		pubKey, err = ecdh.P256().NewPublicKey(peerID)
		if err != nil {
			return
		}
		peerIDBytes = peerID
	}

	challenge := make([]byte, challengeSize)
	_, err = rand.Read(challenge)
	if err != nil {
		return
	}

	challengeResp := make(chan []byte)
	defer close(challengeResp)

	go func() {
		_, data, err := conn.ReadMessage()
		if err != nil {
			return
		}
		challengeResp <- data
	}()

	encryptedChallenge, err := n.encryptChallenge(challenge, pubKey)
	if err != nil {
		return
	}
	conn.WriteMessage(websocket.BinaryMessage, encryptedChallenge)

	select {
	case <-time.After(time.Second):
		return
	case challengeResult, ok := <-challengeResp:
		if !ok {
			return
		}
		if !bytes.Equal(challenge, challengeResult) {
		}
	}

	peerID := peerID(peerIDBytes)
	inbox := make(chan []byte, inboxBufSizePerPeer)

	n.peersMu.RLock()
	peersCount := len(n.peers)
	n.peersMu.RUnlock()

	outbox := n.addConn(pubKey, inbox, peersCount == 0)

	tcpInteraction(inbox, outbox, conn)

	log.Println("Peers count", peersCount)
	if peersCount > 0 {
		n.onboardingsMu.Lock()
		n.onboardings[peerID.Hex256()] = &onboarding{
			Secrets:       [][]byte{},
			RequiresConns: min(peersCount-1, reqConnsCount),
		}
		n.onboardingsMu.Unlock()

		go func() {
			<-time.After(waitConnectionTimeout)
			n.onboardingsMu.Lock()
			delete(n.onboardings, peerID.Hex256())
			n.onboardingsMu.Unlock()

			n.peersMu.RLock()
			p, ok := n.peers[peerID.Hex256()]
			n.peersMu.RUnlock()
			if !ok {
				return
			}
			if p.State == Trusted {
				return
			}
			n.disconnect(peerID.Hex256())
		}()

		n.broadcast(NewSignal(
			SignalTypeNeedPeerInvite,
			pubKey.Bytes(),
			WithRecepient(peerID.Sum256()),
		))
		log.Println("Broadcast onboarding")
	}

}

func (n *Node) encryptChallenge(challenge []byte, verifierECPub *ecdh.PublicKey) ([]byte, error) {
	sharedSecret, err := n.ecdhPrivate.ECDH(verifierECPub)
	if err != nil {
		return nil, fmt.Errorf("generate sharred secret: %w", err)
	}
	sharedKey := sha256.Sum256(sharedSecret)

	block, err := aes.NewCipher(sharedKey[:])
	if err != nil {
		return nil, fmt.Errorf("generate new cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("generate new gsm: %w", err)
	}
	nonce := make([]byte, gcm.NonceSize())
	rand.Read(nonce)

	return gcm.Seal(nonce, nonce, challenge, nil), nil
}

func (n *Node) decryptChallenge(ciphertext []byte, verifierECPub *ecdh.PublicKey) ([]byte, error) {
	sharedSecret, err := n.ecdhPrivate.ECDH(verifierECPub)
	if err != nil {
		return nil, fmt.Errorf("generate sharred secret: %w", err)
	}

	sharedKey := sha256.Sum256(sharedSecret)

	block, err := aes.NewCipher(sharedKey[:])
	if err != nil {
		return nil, fmt.Errorf("generate new cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("generate new gsm: %w", err)
	}
	nonceSize := gcm.NonceSize()
	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]

	return gcm.Open(nil, nonce, ciphertext, nil)
}
