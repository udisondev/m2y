package chat

import (
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"m2y/internal/node"
	"m2y/pkg/crypt"
	"sync"
	"time"
)

type Chat struct {
	ECDHPrivate *ecdh.PrivateKey
	EDPrivate   ed25519.PrivateKey
	EDPublic    ed25519.PublicKey
	BlackList   map[string]struct{}
	Channels    map[string]*Contact
	Node        node.Node
}

type Contact struct {
	Name       string
	ID         string
	Mu         sync.Mutex
	Messages   []Message
	LastRead   int
	Outbox     chan Message
	Disconnect chan struct{}
}

type Message struct {
	Text      string    `json:"text"`
	Author    string    `json:"author"`
	CreatedAt time.Time `json:"created_at"`
}

type Handshake struct {
	PublicKey *ecdh.PublicKey   `json:"public_key"`
	EDPublic  ed25519.PublicKey `json:"ed_public"`
}

func (c *Chat) InitiateChat(ID string) {
	c.Node.InitiateChat(ID)
}

func (c *Chat) Interact(ID string, inbox <-chan []byte) <-chan []byte {
	outbox := make(chan []byte)
	ch, ok := c.Channels[ID]
	if !ok {
		ch = &Contact{
			ID:         ID,
			Messages:   make([]Message, 0),
			Disconnect: make(chan struct{}),
		}
		c.Channels[ID] = ch
	}
	go func() {
		defer close(outbox)

		privateKey, err := ecdh.P521().GenerateKey(rand.Reader)
		if err != nil {
			return
		}

		edPublic, edPrivate, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return
		}

		handshake := Handshake{
			PublicKey: privateKey.PublicKey(),
			EDPublic:  edPublic,
		}

		outHandshake, err := json.Marshal(handshake)
		if err != nil {
			return
		}

		outbox <- outHandshake

		inHandshake := <-inbox
		err = json.Unmarshal(inHandshake, &handshake)
		if err != nil {
			return
		}

		messageOutbox := make(chan Message)

		go func() {
			defer close(messageOutbox)

			for {
				select {
				case <-ch.Disconnect:
					return
				case msg, ok := <-messageOutbox:
					if !ok {
						return
					}
					msgBytes, err := json.Marshal(msg)
					if err != nil {
						continue
					}

					encryptedMsg, err := crypt.EncryptMessage(msgBytes, privateKey, edPrivate, handshake.PublicKey)
					if err != nil {
						continue
					}

					ch.Mu.Lock()
					ch.Messages = append(ch.Messages, msg)
					ch.Mu.Unlock()

					outbox <- encryptedMsg
				}
			}
		}()

		for {
			select {
			case <-ch.Disconnect:
				return
			case in, ok := <-inbox:
				if !ok {
					return
				}
				decryptedMessage, err := crypt.DecryptMessage(in, privateKey, handshake.PublicKey, handshake.EDPublic)
				if err != nil {
					return
				}

				var msg Message
				err = json.Unmarshal(decryptedMessage, &msg)
				if err != nil {
					return
				}

				ch.Mu.Lock()
				ch.Messages = append(ch.Messages, msg)
				ch.Mu.Unlock()
			}

		}

	}()

	return outbox
}
