package node

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"log"
	"m2y/pkg/closer"
	"net/http"
	"sync"
	"time"

	"github.com/pion/webrtc/v4"
)

type (
	Node struct {
		addr string

		id           peerID
		entrypointID peerID

		edPublic    ed25519.PublicKey
		edPrivate   ed25519.PrivateKey
		ecdhPublic  *ecdh.PublicKey
		ecdhPrivate *ecdh.PrivateKey

		peers   map[string]*peer
		peersMu sync.RWMutex

		inbox chan income

		waitOffersMu sync.Mutex
		waitOffers   map[string]offerer

		waitAnswersMu sync.Mutex
		waitAnswers   map[string]answerer

		onboardingsMu sync.RWMutex
		onboardings   map[string]*onboarding

		messageCache messageCache
	}

	offerer struct {
		ecdhPublic *ecdh.PublicKey
		sign       []byte
		secret     []byte
	}

	answerer struct {
		ecdhPublic *ecdh.PublicKey
		pc         *webrtc.PeerConnection
		dc         *webrtc.DataChannel
	}
)

func New(addr string, peersCount int) (Node, error) {
	if addr != "" {
		peersCount = peersCount * 100
	}

	privateECDH, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return Node{}, fmt.Errorf("generate ECDH: %w", err)
	}

	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return Node{}, fmt.Errorf("generate ed25519: %w", err)
	}

	return Node{
		addr:         addr,
		id:           privateECDH.PublicKey().Bytes(),
		peers:        make(map[string]*peer, peersCount),
		inbox:        make(chan income),
		waitOffers:   make(map[string]offerer, peersCount),
		waitAnswers:  make(map[string]answerer, peersCount),
		onboardings:  make(map[string]*onboarding, peersCount),
		edPublic:     public,
		edPrivate:    private,
		ecdhPublic:   privateECDH.PublicKey(),
		ecdhPrivate:  privateECDH,
		messageCache: newMessageCache(),
	}, nil
}

func (n *Node) Run(workersN int) {
	log.Println("My peerID:", n.id.Hex256())
	n.inbox = make(chan income)

	closer.Add(func() error {
		n.peersMu.Lock()
		defer n.peersMu.Unlock()
		for _, p := range n.peers {
			p.Disconnect()
			<-time.After(runCloseWait)
		}
		close(n.inbox)

		return nil
	})

	wg := sync.WaitGroup{}
	wg.Add(workersN)
	for range workersN {
		go func() {
			defer wg.Done()

			for msg := range n.inbox {
				n.dispatch(msg)
			}
		}()
	}

	if n.addr != "" {
		wg.Add(1)
		go func() {
			defer wg.Done()
			server := &http.Server{Addr: n.addr}
			closer.Add(func() error {
				server.Shutdown(context.Background())
				return nil
			})

			http.HandleFunc("/ws", n.handleConnection)
			log.Fatal(server.ListenAndServe())
		}()
	}

	wg.Wait()
}

func (n *Node) addConn(
	pubKey *ecdh.PublicKey,
	inbox <-chan []byte,
	trusted bool,
) <-chan []byte {
	outbox := make(chan []byte, outboxSize)

	pID := peerID(pubKey.Bytes())
	peer := peer{ID: pID}
	if trusted {
		log.Println(pID.Hex256(), "Trusted!")
		peer.State = Trusted
	}

	peer.Disconnect = sync.OnceFunc(func() {
		peer.Mutex.Lock()
		defer peer.Mutex.Unlock()
		peer.State = Disconntected

		close(outbox)
		log.Println(pID.Hex256(), "Disconnected!")
	})

	peer.Send = func(s Signal) {
		n.messageCache.put(s.NonceHex())

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
			go n.disconnect(pID.Hex256())
		}
	}

	n.peersMu.Lock()
	n.peers[pID.Hex256()] = &peer
	n.peersMu.Unlock()

	go func() {
		defer func() {
			n.disconnect(pID.Hex256())
		}()

		for data := range decryptChan(inbox, n.ecdhPrivate, pubKey) {
			var s Signal
			err := s.UnmarshalBinary(data)
			if err != nil {
				return
			}

			if n.messageCache.putIfAbsent(s.NonceHex()) {
				log.Println("Duplicate")
				continue
			}

			n.inbox <- income{
				From:   pID,
				Signal: s,
			}
		}
	}()

	log.Println("New peer:", pID.Hex256())

	return encryptChan(outbox, pubKey, n.ecdhPrivate)
}

func encryptChan(ch <-chan []byte, receiverKey *ecdh.PublicKey, senderKey *ecdh.PrivateKey) <-chan []byte {
	out := make(chan []byte)
	go func() {
		defer close(out)

		for payload := range ch {
			aesKey := make([]byte, aesKeySize)
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
			expectedKeyLen := nonceSize + aesKeySize + 16
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

func (n *Node) broadcast(s Signal) {
	n.peersMu.RLock()
	defer n.peersMu.RUnlock()
	for _, p := range n.peers {
		if p.State < Trusted {
			continue
		}

		p.Send(s)
	}
}

func (n *Node) sendToEntrypoint(s Signal) error {
	n.peersMu.RLock()
	defer n.peersMu.RUnlock()

	peer, ok := n.peers[n.entrypointID.Hex256()]
	if !ok {
		return errors.New("Entrypoint peer not found!")
	}

	peer.Send(s)
	return nil
}

func (n *Node) trust(peerHex string) bool {
	n.peersMu.RLock()
	defer n.peersMu.RUnlock()
	peer, ok := n.peers[peerHex]
	if !ok {
		return false
	}

	peer.Mutex.Lock()
	defer peer.Mutex.Unlock()

	peer.State = Trusted
	return true
}

func (n *Node) disconnect(peerID string) {
	n.peersMu.Lock()
	defer n.peersMu.Unlock()
	peer, ok := n.peers[peerID]
	if !ok {
		return
	}
	peer.Disconnect()

	delete(n.peers, peerID)
}
