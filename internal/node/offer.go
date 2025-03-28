package node

import (
	"bytes"
	"encoding/json"
	"log"
	"m2y/pkg/crypt"
	"time"

	"github.com/pion/webrtc/v4"
)

func offer(n *Node, offerMsg income) {
	if !offerMsg.IsForMe(n.id) {
		n.broadcast(offerMsg.Signal)
		return
	}

	peerHex := ParseHex256(offerMsg.Signal.Sender)
	log.Println("Received offer from:", peerHex)

	n.waitOffersMu.Lock()
	of, ok := n.waitOffers[peerHex]
	n.waitOffersMu.Unlock()
	if !ok {
		return
	}

	decryptedPayload, err := crypt.DecryptMessage(offerMsg.Signal.Payload, n.ecdhPrivate, of.ecdhPublic)
	if err != nil {
		return
	}

	if !bytes.Equal(decryptedPayload[:signLength], of.sign) {
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

	pc.OnDataChannel(func(dataChannel *webrtc.DataChannel) {
		dataChannel.OnOpen(func() {
			n.waitOffersMu.Lock()
			delete(n.waitOffers, peerHex)
			n.waitOffersMu.Unlock()

			inbox := make(chan []byte)

			pong := make(chan struct{})

			dataChannel.OnClose(func() {
				close(inbox)
			})

			go func() {
				defer n.disconnect(peerHex)

				for {
					select {
					case <-time.After(pongWaitTime):
						return
					case <-pong:
						continue
					}
				}
			}()

			dataChannel.OnMessage(func(msg webrtc.DataChannelMessage) {
				if bytes.Equal(msg.Data, pingSignal) {
					log.Println("RTC Ping")
					dataChannel.Send(pongSignal)
					return
				}
				if bytes.Equal(msg.Data, pongSignal) {
					log.Println("RTC Pong")
					pong <- struct{}{}
					return
				}
				inbox <- msg.Data
			})

			outbox := n.addConn(
				of.ecdhPublic,
				inbox,
				true)

			go func() {
				defer func() {
					pc.Close()
					dataChannel.Close()
				}()

				pingTicker := time.NewTicker(pingPeriod)
				for {
					select {
					case <-pingTicker.C:
						dataChannel.Send(pingSignal)
					case data, work := <-outbox:
						if !work {
							return
						}

						dataChannel.Send(data)
					}
				}
			}()

			n.peersMu.RLock()
			pID := peerID(of.ecdhPublic.Bytes())
			n.peersMu.RUnlock()

			peer, ok := n.peers[pID.Hex256()]
			if !ok {
				return
			}

			go peer.Send(NewSignal(
				SignalTypeConnectionSecret,
				of.secret,
			))
			log.Println("Connection secret was sent to:", pID.Hex256())
		})
	})

	var sd webrtc.SessionDescription
	json.Unmarshal(decryptedPayload[signLength:], &sd)
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

	encryptedPayload, err := crypt.EncryptMessage(anserSDP, n.ecdhPrivate, n.edPrivate, n.edPublic, of.ecdhPublic)
	if err != nil {
		return
	}

	n.broadcast(NewSignal(
		SignalTypePeerAnswer,
		encryptedPayload,
		WithRecepient(offerMsg.Signal.Sender),
		WithSender(n.id.Sum256()),
	))

	log.Println("Answer was sent to:", peerHex)
}
