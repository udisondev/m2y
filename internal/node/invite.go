package node

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"log"
	"m2y/pkg/crypt"
	"time"

	"github.com/pion/webrtc/v4"
)

func needInvite(n *Node, invReq income) {
	log.Println("Received invite request")
	if len(n.peers) > maxPeersCount {
		log.Println("Has no free peer slot")
		n.broadcast(invReq.Signal)
		return
	}

	peerID := peerID(invReq.Signal.Payload)
	pubKey, err := ecdh.P256().NewPublicKey(invReq.Signal.Payload)
	if err != nil {
		return
	}

	sign := make([]byte, signLength)
	_, err = rand.Read(sign)
	if err != nil {
		return
	}

	encryptedPayload, err := crypt.EncryptPeerMessage(sign, n.ecdhPrivate, n.edPrivate, n.edPublic, pubKey)
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

	n.waitPeerOffersMu.Lock()
	n.waitPeerOffers[peerID.Hex256()] = offerer{
		ecdhPublic: pubKey,
		sign:       sign,
		secret:     secret,
	}
	n.waitPeerOffersMu.Unlock()

	go func() {
		<-time.After(waitOfferTimeout)
		log.Println("Offer removed")
		n.waitPeerOffersMu.Lock()
		delete(n.waitPeerOffers, peerID.Hex256())
		n.waitPeerOffersMu.Unlock()
	}()

	n.broadcast(NewSignal(
		SignalTypePeerInvite,
		encryptedPayload,
		WithRecepient(invReq.Signal.Receipient),
	))

	log.Println("Invite was sent to:", ParseHex256(invReq.Signal.Receipient))
}

func invite(n *Node, inviteMsg income) {
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

func handleMineInvite(n *Node, inviteMsg income) {
	peerID := peerID(inviteMsg.Signal.Payload[:ecdhPubKeyLength])
	log.Println("Received invite from:", peerID.Hex256())

	pubKey, err := peerID.PubKey()
	if err != nil {
		return
	}

	decryptedPayload, err := crypt.DecryptPeerMessage(inviteMsg.Signal.Payload[ecdhPubKeyLength:], n.ecdhPrivate, pubKey)
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
	encryptedPayload, err := crypt.EncryptPeerMessage(payload, n.ecdhPrivate, n.edPrivate, n.edPublic, pubKey)
	if err != nil {
		return
	}

	n.waitPeerAnswersMu.Lock()
	n.waitPeerAnswers[peerID.Hex256()] = answerer{
		ecdhPublic: pubKey,
		pc:         pc,
		dc:         dc,
	}
	n.waitPeerAnswersMu.Unlock()

	go func() {
		<-time.After(waitOfferTimeout)
		log.Println("Answer removed")
		n.waitPeerAnswersMu.Lock()
		delete(n.waitPeerAnswers, peerID.Hex256())
		n.waitPeerAnswersMu.Unlock()
	}()

	err = n.sendToEntrypoint(NewSignal(
		SignalTypePeerOffer,
		encryptedPayload,
		WithRecepient(peerID.Sum256()),
		WithSender(n.id.Sum256()),
	))
	if err != nil {
		return
	}
	log.Println("Offer was send to:", peerID.Hex256())
}

func chatInvite(n *Node, inviteMsg income) {
	myPeerID := peerID(n.client.ECDHPrivate().PublicKey().Bytes())
	if !inviteMsg.IsForMe(myPeerID) {
		n.broadcast(inviteMsg.Signal)
		return
	}

	peerID := peerID(inviteMsg.Signal.Payload[:ecdhPubKeyLength])
	log.Println("Received chat invite from:", peerID.Hex256())
	if !n.client.Welcome(peerID.Hex()) {
		return
	}

	pubKey, err := peerID.PubKey()
	if err != nil {
		return
	}

	decryptedPayload, err := crypt.DecryptPeerMessage(inviteMsg.Signal.Payload[ecdhPubKeyLength:], n.ecdhPrivate, pubKey)
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
	encryptedPayload, err := crypt.EncryptPeerMessage(payload, n.ecdhPrivate, n.edPrivate, n.edPublic, pubKey)
	if err != nil {
		return
	}

	n.waitPeerAnswersMu.Lock()
	n.waitPeerAnswers[peerID.Hex256()] = answerer{
		ecdhPublic: pubKey,
		pc:         pc,
		dc:         dc,
	}
	n.waitPeerAnswersMu.Unlock()

	go func() {
		<-time.After(waitOfferTimeout)
		log.Println("Answer removed")
		n.waitPeerAnswersMu.Lock()
		delete(n.waitPeerAnswers, peerID.Hex256())
		n.waitPeerAnswersMu.Unlock()
	}()

	n.broadcast(NewSignal(
		SignalTypeChatOffer,
		encryptedPayload,
		WithRecepient(peerID.Sum256()),
		WithSender(myPeerID.Sum256()),
	))
	if err != nil {
		return
	}
	log.Println("ChatOffer was send to:", peerID.Hex256())
}
