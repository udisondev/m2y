package node

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"log"
	"m2y/pkg/crypt"

	"github.com/pion/webrtc/v4"
)

func needInvite(n *node, invReq income) {
	log.Println("Received invite request")
	if len(n.peers) > maxPeersCount {
		n.broadcast(invReq.Signal)
		return
	}

	peerID := peerID(invReq.Signal.Payload)
	pubKey, err := ecdh.P256().NewPublicKey(invReq.Signal.Payload)
	if err != nil {
		log.Panicln("Error parse public key", err)
		return
	}

	sign := make([]byte, signLength)
	_, err = rand.Read(sign)
	if err != nil {
		return
	}

	encryptedPayload, err := crypt.EncryptMessage(sign, n.ecdhPrivate, n.edPrivate, n.edPublic, pubKey)
	if err != nil {
		return
	}

	secret := make([]byte, connectionProofLength)
	_, err = rand.Read(secret)
	if err != nil {
		return
	}

	encryptedPayload = append(n.ecdhPublic.Bytes(), encryptedPayload...)
	encryptedPayload = append(secret, encryptedPayload...)

	n.waitOffersMu.Lock()
	n.waitOffers[peerID.Hex256()] = offerer{
		ecdhPublic: pubKey,
		sign:       sign,
		secret:     secret,
	}
	n.waitOffersMu.Unlock()
	n.broadcast(NewSignal(
		SignalTypePeerInvite,
		encryptedPayload,
		WithRecepient(invReq.Signal.Receipient),
	))

	log.Println("Invite was sent to:", ParseHex256(invReq.Signal.Receipient))
}

func invite(n *node, inviteMsg income) {
	recipientHex := ParseHex256(inviteMsg.Signal.Receipient)

	n.onboardingsMu.RLock()
	onboarding, hasWaiters := n.onboardings[recipientHex]
	n.onboardingsMu.RUnlock()

	switch {
	case inviteMsg.IsForMe(n.id):
		handleMineInvite(n, inviteMsg)
	case hasWaiters:
		n.peersMu.RLock()
		peer, hasWaiters := n.peers[hex.EncodeToString(inviteMsg.Signal.Receipient[:])]
		n.peersMu.RUnlock()
		if !hasWaiters {
			return
		}

		secret := inviteMsg.Signal.Payload[:connectionProofLength]
		if ok := onboarding.AddSecret(secret); !ok {
			return
		}

		inviteMsg.Signal.Payload = inviteMsg.Signal.Payload[connectionProofLength:]
		peer.Send(inviteMsg.Signal)
	default:
		return
	}
}

func handleMineInvite(n *node, inviteMsg income) {
	pID := peerID(inviteMsg.Signal.Payload[:ecdhPubKeyLength])
	log.Println("Received invite from:", pID.Hex256())

	pubKey, err := pID.PubKey()
	if err != nil {
		return
	}

	decryptedPayload, err := crypt.DecryptMessage(inviteMsg.Signal.Payload[ecdhPubKeyLength:], n.ecdhPrivate, pubKey)
	if err != nil {
		return
	}

	config := webrtc.Configuration{
		ICEServers: []webrtc.ICEServer{
			{
				URLs: []string{
					"stun:stun.l.google.com:19302",
				},
			},
		},
	}
	pc, err := webrtc.NewPeerConnection(config)
	if err != nil {
		return
	}

	defer func() {
		if err == nil {
			return
		}
		pc.Close()
	}()

	dc, err := pc.CreateDataChannel("network", nil)
	if err != nil {
		return
	}
	defer func() {
		if err == nil {
			return
		}
		dc.Close()
	}()

	offer, err := pc.CreateOffer(nil)
	if err != nil {
		return
	}

	if err := pc.SetLocalDescription(offer); err != nil {
		return
	}
	SDP, err := json.Marshal(pc.LocalDescription())
	if err != nil {
		return
	}

	sign := decryptedPayload
	payload := append(sign, SDP...)
	encryptedPayload, err := crypt.EncryptMessage(payload, n.ecdhPrivate, n.edPrivate, n.edPublic, pubKey)
	if err != nil {
		return
	}

	n.waitAnswersMu.Lock()
	n.waitAnswers[pID.Hex256()] = answerer{
		ecdhPublic: pubKey,
		pc:         pc,
		dc:         dc,
	}
	n.waitAnswersMu.Unlock()

	err = n.sendToEntrypoint(NewSignal(
		SignalTypePeerOffer,
		encryptedPayload,
		WithRecepient(pID.Sum256()),
		WithSender(n.id.Sum256()),
	))
	if err != nil {
		return
	}
	log.Println("Offer was send to:", pID.Hex256())
}
