package node

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"log"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/pion/webrtc/v4"
)

type Node struct {
	Addr string

	ID PeerID

	EntrypointID PeerID
	EDPublic     ed25519.PublicKey  // Идентификатор ноды
	EDPrivate    ed25519.PrivateKey // Приватный ключ для подписи
	ECDHPublic   *ecdh.PublicKey    // Публичный ключ для ECDH
	ECDHPrivate  *ecdh.PrivateKey

	Peers   map[string]*Peer
	PeersMu sync.RWMutex

	Inbox chan Income

	WaitOffersMu sync.Mutex
	WaitOffers   map[string]Offerer

	WaitAnswersMu sync.Mutex
	WaitAnswers   map[string]Answerer

	OnboardingsMu sync.RWMutex
	Onboardings   map[string]*Onboarding

	duplicatedBytesMu sync.Mutex
	duplicatedBytes   map[string]struct{}
}

type Offerer struct {
	ECDHPublic *ecdh.PublicKey // Публичный ключ для ECDH
	Sign       []byte
	Secret     []byte
}

type Answerer struct {
	ECDHPublic *ecdh.PublicKey // Публичный ключ для ECDH
	PC         *webrtc.PeerConnection
	DC         *webrtc.DataChannel
}

type PeerID []byte

func (p PeerID) Sum256() []byte {
	hash := sha256.Sum256(p)
	return hash[:]
}

func (p PeerID) Hex256() string {
	return hex.EncodeToString(p.Sum256())
}

func ParseHex256(b []byte) string {
	return hex.EncodeToString(b)
}

// ChallengeRequest запрос испытания
type ChallengeRequest struct {
	EncryptedChallenge []byte `json:"encrypted_challenge"`
}

// ChallengeResponse ответ на испытание
type ChallengeResponse struct {
	DecryptedChallenge []byte `json:"decrypted_challenge"`
}

type Peer struct {
	ID         PeerID
	Disconnect func()
	Send       func(Signal)
	State      PeerState
	Mutex      sync.RWMutex
}

type Onboarding struct {
	Mu               sync.Mutex
	Secrets          [][]byte
	RequiresConns    int
	ConnectionProofs int
}

func (o *Onboarding) AddSecret(s []byte) bool {
	o.Mu.Lock()
	defer o.Mu.Unlock()
	if len(o.Secrets) >= 5 {
		return false
	}
	o.Secrets = append(o.Secrets, s)
	return true
}

type PeerState int8

const (
	Disconntected PeerState = iota - 1
	Verified
	Trusted
)

func New(addr string) (*Node, error) {
	edPub, edPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}

	ecdhPriv, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}

	return &Node{
		Addr:        addr,
		EDPublic:    edPub,
		EDPrivate:   edPriv,
		ECDHPublic:  ecdhPriv.PublicKey(),
		ECDHPrivate: ecdhPriv,
		Peers:       make(map[string]*Peer),
	}, nil
}

func (n *Node) Start() {
	if n.Addr == "" {
		return
	}
	http.HandleFunc("/ws", n.handleConnection)
	log.Fatal(http.ListenAndServe(n.Addr, nil))
}

func (n *Node) Run(workersN int) {
	log.Println("My peerID:", n.ID.Hex256())

	n.duplicatedBytes = map[string]struct{}{}
	n.Inbox = make(chan Income)

	termSig := make(chan os.Signal, 1)
	signal.Notify(termSig, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-termSig
		n.PeersMu.Lock()
		defer n.PeersMu.Unlock()
		for _, p := range n.Peers {
			p.Disconnect()
		}
		close(n.Inbox)
		<-time.After(time.Second * 5)
		os.Exit(1)
	}()

	wg := sync.WaitGroup{}
	wg.Add(workersN)
	for range workersN {
		go func() {
			defer wg.Done()

			for msg := range n.Inbox {
				n.dispatch(msg)
			}
		}()
	}
	wg.Wait()
}

func (n *Node) broadcast(s Signal) {
	n.PeersMu.RLock()
	defer n.PeersMu.RUnlock()
	for _, p := range n.Peers {
		if p.State < Trusted {
			continue
		}

		p.Send(s)
	}
}

func (n *Node) SendToEntrypoint(s Signal) error {
	n.PeersMu.RLock()
	defer n.PeersMu.RUnlock()

	peer, ok := n.Peers[n.EntrypointID.Hex256()]
	if !ok {
		return errors.New("Entrypoint peer not found!")
	}

	peer.Send(s)
	return nil
}

func (n *Node) Trust(peerHex string) bool {
	n.PeersMu.RLock()
	defer n.PeersMu.RUnlock()
	peer, ok := n.Peers[peerHex]
	if !ok {
		return false
	}

	peer.Mutex.Lock()
	defer peer.Mutex.Unlock()

	peer.State = Trusted
	return true
}
