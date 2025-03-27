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
	"sync"
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

	err = conn.WriteMessage(websocket.BinaryMessage, n.ECDHPublic.Bytes())
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

	peerID := PeerID(peerIDBytes)
	n.EntrypointID = peerID

	inbox := make(chan []byte)
	outbox := n.addConn(pubKey, inbox, true)
	tcpInteraction(inbox, outbox, conn)

	return nil
}

func tcpInteraction(inbox chan<- []byte, outbox <-chan []byte, conn *websocket.Conn) {
	ping := make(chan struct{})
	pong := make(chan struct{})
	isDead := make(chan struct{})

	outbox = func(ch <-chan []byte) <-chan []byte {
		out := make(chan []byte, 256)

		go func() {
			defer close(out)
			defer conn.Close()

			pingTicker := time.NewTicker(time.Second * 7)
			for {
				select {
				case <-ping:
					out <- []byte{0xFF}
				case <-pingTicker.C:
					out <- []byte{0xFE}
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

			if bytes.Equal(data, []byte{0xFE}) {
				log.Println("Ping")
				ping <- struct{}{}
				continue
			}

			if bytes.Equal(data, []byte{0xFF}) {
				log.Println("Pong")
				pong <- struct{}{}
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
			case <-pong:
				continue
			case <-time.After(time.Second * 11):
				return
			}
		}
	}()
}

func (n *Node) addConn(
	pubKey *ecdh.PublicKey,
	inbox <-chan []byte,
	trusted bool,
) <-chan []byte {
	outbox := make(chan []byte, 256)

	peerID := PeerID(pubKey.Bytes())
	peer := Peer{ID: peerID}
	if trusted {
		log.Println(peerID.Hex256(), "Trusted!")
		peer.State = Trusted
	}

	peer.Disconnect = sync.OnceFunc(func() {
		peer.Mutex.Lock()
		defer peer.Mutex.Unlock()
		peer.State = Disconntected

		close(outbox)
		log.Println(peerID.Hex256(), "Disconnected!")
	})

	peer.Send = func(s Signal) {
		n.duplicatedBytesMu.Lock()
		n.duplicatedBytes[s.NonceHex()] = struct{}{}
		n.duplicatedBytesMu.Unlock()

		peer.Mutex.RLock()
		defer peer.Mutex.RUnlock()

		if peer.State == Disconntected {
			return
		}

		out, err := s.MarshalBinary()
		if err != nil {
			return
		}

		select {
		case outbox <- out:
		default:
			go n.Disconnect(peerID.Hex256())
		}
	}

	n.PeersMu.Lock()
	n.Peers[peerID.Hex256()] = &peer
	n.PeersMu.Unlock()

	go func() {
		defer func() {
			n.Disconnect(peerID.Hex256())
		}()

		for data := range decryptChan(inbox, n.ECDHPrivate, pubKey) {
			var s Signal
			err := s.UnmarshalBinary(data)
			if err != nil {
				return
			}

			n.duplicatedBytesMu.Lock()
			_, ok := n.duplicatedBytes[s.NonceHex()]
			n.duplicatedBytesMu.Unlock()
			if ok {
				continue
			}
			n.duplicatedBytesMu.Lock()
			n.duplicatedBytes[s.NonceHex()] = struct{}{}
			n.duplicatedBytesMu.Unlock()

			n.Inbox <- Income{
				From:   peerID,
				Signal: s,
			}
		}
	}()

	log.Println("New peer:", peerID.Hex256())

	return encryptChan(outbox, pubKey, n.ECDHPrivate)
}

func encryptChan(ch <-chan []byte, receiverKey *ecdh.PublicKey, senderKey *ecdh.PrivateKey) <-chan []byte {
	out := make(chan []byte)
	go func() {
		defer close(out)

		for payload := range ch {
			aesKey := make([]byte, 32)
			if _, err := rand.Read(aesKey); err != nil {
				return
			}

			block, err := aes.NewCipher(aesKey)
			if err != nil {
				return
			}
			gcm, err := cipher.NewGCM(block)
			if err != nil {
				return
			}
			nonceAES := make([]byte, gcm.NonceSize())
			if _, err := rand.Read(nonceAES); err != nil {
				return
			}
			encryptedPayload := gcm.Seal(nonceAES, nonceAES, payload, nil)

			sharedSecret, err := senderKey.ECDH(receiverKey)
			if err != nil {
				return
			}
			sharedKey := sha256.Sum256(sharedSecret)
			keyBlock, err := aes.NewCipher(sharedKey[:])
			if err != nil {
				return
			}
			keyGCM, err := cipher.NewGCM(keyBlock)
			if err != nil {
				return
			}
			keyNonce := make([]byte, keyGCM.NonceSize())
			if _, err := rand.Read(keyNonce); err != nil {
				return
			}
			encryptedAESKey := keyGCM.Seal(keyNonce, keyNonce, aesKey, nil)

			out <- append(encryptedAESKey, encryptedPayload...)
		}
	}()

	return out
}
func decryptChan(ch <-chan []byte, receverKey *ecdh.PrivateKey, senderKey *ecdh.PublicKey) <-chan []byte {
	out := make(chan []byte)
	go func() {
		defer close(out)
		for data := range ch {
			sharedSecret, err := receverKey.ECDH(senderKey)
			if err != nil {
				return
			}
			sharedKey := sha256.Sum256(sharedSecret)
			keyBlock, err := aes.NewCipher(sharedKey[:])
			if err != nil {
				return
			}
			keyGCM, err := cipher.NewGCM(keyBlock)
			if err != nil {
				return
			}
			nonceSize := keyGCM.NonceSize()
			expectedKeyLen := nonceSize + 32 + 16
			if len(data) < expectedKeyLen {
				return
			}

			encryptedAESKey := data[:expectedKeyLen]
			aesKey, err := keyGCM.Open(nil, encryptedAESKey[:nonceSize], encryptedAESKey[nonceSize:], nil)
			if err != nil {
				return
			}

			encryptedPayload := data[expectedKeyLen:]
			block, err := aes.NewCipher(aesKey)
			if err != nil {
				return
			}
			gcm, err := cipher.NewGCM(block)
			if err != nil {
				return
			}
			if len(encryptedPayload) < gcm.NonceSize() {
				return
			}
			nonce := encryptedPayload[:gcm.NonceSize()]
			ciphertext := encryptedPayload[gcm.NonceSize():]
			decryptedPayload, err := gcm.Open(nil, nonce, ciphertext, nil)
			if err != nil {
				return
			}

			out <- decryptedPayload
		}
	}()
	return out
}

func (n *Node) handleConnection(w http.ResponseWriter, r *http.Request) {
	upgrader := websocket.Upgrader{
		ReadBufferSize:  1024,
		WriteBufferSize: 1024,
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
		if len(data) != 65 {
			return
		}
		peerIDResp <- data
	}()

	err = conn.WriteMessage(websocket.BinaryMessage, n.ECDHPublic.Bytes())
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

	challenge := make([]byte, 32)
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

	peerID := PeerID(peerIDBytes)
	inbox := make(chan []byte, 10)
	trusted := len(n.Peers) == 0
	outbox := n.addConn(pubKey, inbox, trusted)
	tcpInteraction(inbox, outbox, conn)

	n.PeersMu.RLock()
	peersCount := len(n.Peers)
	n.PeersMu.RUnlock()

	if peersCount > 1 {
		n.OnboardingsMu.Lock()
		n.Onboardings[peerID.Hex256()] = &Onboarding{
			Secrets:       [][]byte{},
			RequiresConns: min(peersCount-1, 5),
		}
		n.OnboardingsMu.Unlock()

		n.broadcast(NewSignal(
			SignalTypeNeedPeerInvite,
			pubKey.Bytes(),
			WithRecepient(peerID.Sum256()),
		))
	}

}

func (n *Node) encryptChallenge(challenge []byte, verifierECPub *ecdh.PublicKey) ([]byte, error) {
	sharedSecret, err := n.ECDHPrivate.ECDH(verifierECPub)
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
	sharedSecret, err := n.ECDHPrivate.ECDH(verifierECPub)
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

func (n *Node) Disconnect(peerID string) {
	n.PeersMu.Lock()
	defer n.PeersMu.Unlock()
	peer, ok := n.Peers[peerID]
	if !ok {
		return
	}
	peer.Disconnect()

	delete(n.Peers, peerID)
}
