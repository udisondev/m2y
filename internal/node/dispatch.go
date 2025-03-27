package node

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"log"
	"m2y/pkg/crypt"
	"time"

	"github.com/pion/webrtc/v4"
)

var handlers = map[SignalType]func(*Node, Income){
	SignalTypeNeedPeerInvite:   needInvite,
	SignalTypePeerInvite:       invite,
	SignalTypePeerOffer:        offer,
	SignalTypePeerAnswer:       answer,
	SignalTypeConnectionSecret: secret,
	SignalTypeConnectionProof:  connectionProof,
}

func (n *Node) dispatch(msg Income) {
	h, ok := handlers[msg.Signal.Type]
	if !ok {
		log.Println("Has no handler for:", msg.Signal.Type)
		return
	}
	h(n, msg)
}

func needInvite(n *Node, invReq Income) {
	log.Println("Received invite request")
	if len(n.Peers) > 5 {
		n.broadcast(invReq.Signal)
		return
	}

	peerID := PeerID(invReq.Signal.Payload)
	pubKey, err := ecdh.P256().NewPublicKey(invReq.Signal.Payload)
	if err != nil {
		log.Panicln("Error parse public key", err)
		return
	}

	sign := make([]byte, 32)
	_, err = rand.Read(sign)
	if err != nil {
		return
	}

	encryptedPayload, err := crypt.EncryptMessage(sign, n.ECDHPrivate, n.EDPrivate, n.EDPublic, pubKey)
	if err != nil {
		return
	}

	secret := make([]byte, 12)
	_, err = rand.Read(secret)
	if err != nil {
		return
	}

	encryptedPayload = append(n.ECDHPublic.Bytes(), encryptedPayload...)
	encryptedPayload = append(secret, encryptedPayload...)

	n.WaitOffersMu.Lock()
	n.WaitOffers[peerID.Hex256()] = Offerer{
		ECDHPublic: pubKey,
		Sign:       sign,
		Secret:     secret,
	}
	n.WaitOffersMu.Unlock()
	n.broadcast(NewSignal(
		SignalTypePeerInvite,
		encryptedPayload,
		WithRecepient(invReq.Signal.Receipient),
	))

	log.Println("Invite was sent to:", ParseHex256(invReq.Signal.Receipient))
}

func invite(n *Node, inviteMsg Income) {
	recipientHex := ParseHex256(inviteMsg.Signal.Receipient)

	n.OnboardingsMu.RLock()
	onboarding, hasWaiters := n.Onboardings[recipientHex]
	n.OnboardingsMu.RUnlock()

	switch {
	case inviteMsg.IsForMe(n.ID):
		handleMineInvite(n, inviteMsg)
	case hasWaiters:
		n.PeersMu.RLock()
		peer, hasWaiters := n.Peers[hex.EncodeToString(inviteMsg.Signal.Receipient[:])]
		n.PeersMu.RUnlock()
		if !hasWaiters {
			return
		}

		secret := inviteMsg.Signal.Payload[:12]
		if ok := onboarding.AddSecret(secret); !ok {
			return
		}

		inviteMsg.Signal.Payload = inviteMsg.Signal.Payload[12:]
		peer.Send(inviteMsg.Signal)
	default:
		return
	}
}

func handleMineInvite(n *Node, inviteMsg Income) {
	peerID := PeerID(inviteMsg.Signal.Payload[:65])
	log.Println("Received invite from:", peerID.Hex256())

	pubKey, err := ecdh.P256().NewPublicKey(inviteMsg.Signal.Payload[:65])
	if err != nil {
		return
	}

	decryptedPayload, err := crypt.DecryptMessage(inviteMsg.Signal.Payload[65:], n.ECDHPrivate, pubKey)
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
	encryptedPayload, err := crypt.EncryptMessage(payload, n.ECDHPrivate, n.EDPrivate, n.EDPublic, pubKey)
	if err != nil {
		return
	}

	n.WaitAnswersMu.Lock()
	n.WaitAnswers[peerID.Hex256()] = Answerer{
		ECDHPublic: pubKey,
		PC:         pc,
		DC:         dc,
	}
	n.WaitAnswersMu.Unlock()

	err = n.SendToEntrypoint(NewSignal(
		SignalTypePeerOffer,
		encryptedPayload,
		WithRecepient(peerID.Sum256()),
		WithSender(n.ID.Sum256()),
	))
	if err != nil {
		return
	}
	log.Println("Offer was send to:", peerID.Hex256())
}

func offer(n *Node, offerMsg Income) {
	if !offerMsg.IsForMe(n.ID) {
		n.broadcast(offerMsg.Signal)
		return
	}

	peerHex := ParseHex256(offerMsg.Signal.Sender)
	log.Println("Received offer from:", peerHex)

	n.WaitOffersMu.Lock()
	of, ok := n.WaitOffers[peerHex]
	n.WaitOffersMu.Unlock()
	if !ok {
		return
	}

	decryptedPayload, err := crypt.DecryptMessage(offerMsg.Signal.Payload, n.ECDHPrivate, of.ECDHPublic)
	if err != nil {
		return
	}

	if !bytes.Equal(decryptedPayload[:32], of.Sign) {
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
	defer func() {
		if err == nil {
			return
		}
		pc.Close()
	}()
	if err != nil {
		return
	}

	pc.OnConnectionStateChange(func(state webrtc.PeerConnectionState) {
		if state == webrtc.PeerConnectionStateClosed {
		}
	})

	pc.OnDataChannel(func(dataChannel *webrtc.DataChannel) {
		dataChannel.OnOpen(func() {
			n.WaitOffersMu.Lock()
			delete(n.WaitOffers, peerHex)
			n.WaitOffersMu.Unlock()

			inbox := make(chan []byte)

			pong := make(chan struct{})

			dataChannel.OnClose(func() {
				log.Println("Datachannel closed")
				close(inbox)
			})

			go func() {
				defer n.Disconnect(peerHex)

				for {
					select {
					case <-time.After(time.Second * 11):
						return
					case <-pong:
						continue
					}
				}
			}()

			dataChannel.OnMessage(func(msg webrtc.DataChannelMessage) {
				if bytes.Equal(msg.Data, []byte{0xFE}) {
					log.Println("RTC Ping")
					dataChannel.Send([]byte{0xFF})
					return
				}
				if bytes.Equal(msg.Data, []byte{0xFF}) {
					log.Println("RTC Pong")
					pong <- struct{}{}
					return
				}
				inbox <- msg.Data
			})

			outbox := n.addConn(
				of.ECDHPublic,
				inbox,
				true)

			go func() {
				defer func() {
					log.Println("RTC outbox closed")
					pc.Close()
					dataChannel.Close()
				}()

				pingTicker := time.NewTicker(time.Second * 7)
				for {
					select {
					case <-pingTicker.C:
						dataChannel.Send([]byte{0xFE})
					case data, work := <-outbox:
						if !work {
							log.Println("oubox closed!")
							return
						}

						dataChannel.Send(data)
					}
				}
			}()

			n.PeersMu.RLock()
			peerID := PeerID(of.ECDHPublic.Bytes())
			n.PeersMu.RUnlock()

			peer, ok := n.Peers[peerID.Hex256()]
			if !ok {
				return
			}

			peer.Send(NewSignal(
				SignalTypeConnectionSecret,
				of.Secret,
			))
			log.Println("Connection secret was sent to:", peerID.Hex256())
		})
	})

	var sd webrtc.SessionDescription
	json.Unmarshal(decryptedPayload[32:], &sd)
	err = pc.SetRemoteDescription(sd)
	if err != nil {
		return
	}

	answer, err := pc.CreateAnswer(nil)
	if err != nil {
		return
	}

	gatherComplete := webrtc.GatheringCompletePromise(pc)

	err = pc.SetLocalDescription(answer)
	if err != nil {
		return
	}

	<-gatherComplete
	anserSDP, err := json.Marshal(pc.LocalDescription())
	if err != nil {
		return
	}

	encryptedPayload, err := crypt.EncryptMessage(anserSDP, n.ECDHPrivate, n.EDPrivate, n.EDPublic, of.ECDHPublic)
	if err != nil {
		return
	}

	n.broadcast(NewSignal(
		SignalTypePeerAnswer,
		encryptedPayload,
		WithRecepient(offerMsg.Signal.Sender),
		WithSender(n.ID.Sum256()),
	))

	log.Println("Answer was sent to:", peerHex)
}

func answer(n *Node, answerMsg Income) {
	n.OnboardingsMu.RLock()
	_, hasAnswerWaiters := n.Onboardings[answerMsg.RecepientHex256()]
	n.OnboardingsMu.RUnlock()

	switch {
	case hasAnswerWaiters:
		n.PeersMu.RLock()
		peer, ok := n.Peers[answerMsg.RecepientHex256()]
		n.PeersMu.RUnlock()

		if !ok {
			return
		}

		peer.Send(answerMsg.Signal)
		log.Println("Answer was sent to waiter")
	case answerMsg.IsForMe(n.ID):
		handleMineAnswer(n, answerMsg)
	default:
		n.broadcast(answerMsg.Signal)
		log.Println("Answer was broadcasted")
	}

}

func handleMineAnswer(n *Node, answerMsg Income) {
	peerHex := ParseHex256(answerMsg.Signal.Sender)
	log.Println("Received aswer from:", peerHex)

	n.WaitAnswersMu.Lock()
	ans, ok := n.WaitAnswers[peerHex]
	n.WaitAnswersMu.Unlock()
	if !ok {
		return
	}

	decryptedPayload, err := crypt.DecryptMessage(answerMsg.Signal.Payload, n.ECDHPrivate, ans.ECDHPublic)
	if err != nil {
		return
	}
	var ansSDP webrtc.SessionDescription
	err = json.Unmarshal(decryptedPayload, &ansSDP)
	if err != nil {
		return
	}

	ans.DC.OnOpen(func() {
		n.WaitAnswersMu.Lock()
		delete(n.WaitAnswers, peerHex)
		n.WaitAnswersMu.Unlock()
		inbox := make(chan []byte)

		pong := make(chan struct{})
		ans.DC.OnClose(func() {
			close(inbox)
		})
		go func() {
			defer n.Disconnect(peerHex)

			for {
				select {
				case <-time.After(time.Second * 11):
					return
				case <-pong:
					continue
				}
			}
		}()

		ans.DC.OnMessage(func(msg webrtc.DataChannelMessage) {
			if bytes.Equal(msg.Data, []byte{0xFE}) {
				log.Println("RTC Ping")
				ans.DC.Send([]byte{0xFF})
				return
			}
			if bytes.Equal(msg.Data, []byte{0xFF}) {
				log.Println("RTC Pong")
				pong <- struct{}{}
				return
			}
			inbox <- msg.Data
		})

		outbox := n.addConn(
			ans.ECDHPublic,
			inbox,
			true)

		go func() {
			defer func() {
				log.Println("RTC outbox closed")
				ans.PC.Close()
				ans.DC.Close()
			}()

			pingTicker := time.NewTicker(time.Second * 7)
			for {
				select {
				case <-pingTicker.C:
					ans.DC.Send([]byte{0xFE})
				case data, work := <-outbox:
					if !work {
						log.Println("oubox closed!")
						return
					}

					ans.DC.Send(data)
				}
			}
		}()

	})

	ans.PC.SetRemoteDescription(ansSDP)
}

func secret(n *Node, msg Income) {
	err := n.SendToEntrypoint(NewSignal(
		SignalTypeConnectionProof,
		msg.Signal.Payload,
	))
	if err != nil {
		return
	}
	log.Println("Secret was sent")

}

func connectionProof(n *Node, msg Income) {
	peerHex := msg.From.Hex256()
	n.OnboardingsMu.Lock()
	defer n.OnboardingsMu.Unlock()

	onboarding, ok := n.Onboardings[peerHex]
	if !ok {
		return
	}

	for _, sec := range onboarding.Secrets {
		if !bytes.Equal(sec, msg.Signal.Payload) {
			continue
		}

		log.Println("Receved secret from:", peerHex)
		onboarding.ConnectionProofs++

		if onboarding.RequiresConns == onboarding.ConnectionProofs {
			n.Trust(peerHex)
			log.Println(peerHex, "are trusted yet!")
			delete(n.Onboardings, peerHex)
		}
		return
	}

}
