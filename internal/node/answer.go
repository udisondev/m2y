package node

import (
	"bytes"
	"encoding/json"
	"log"
	"m2y/pkg/crypt"
	"time"

	"github.com/pion/webrtc/v4"
)

func answer(n *Node, answerMsg income) {
	n.onboardingsMu.RLock()
	_, hasAnswerWaiters := n.onboardings[answerMsg.RecepientHex256()]
	n.onboardingsMu.RUnlock()

	switch {
	case hasAnswerWaiters:
		n.peersMu.RLock()
		peer, ok := n.peers[answerMsg.RecepientHex256()]
		n.peersMu.RUnlock()

		if !ok {
			return
		}

		peer.Send(answerMsg.Signal)
		log.Println("Answer was sent to waiter")
	case answerMsg.IsForMe(n.id):
		handleMineAnswer(n, answerMsg)
	default:
		n.broadcast(answerMsg.Signal)
		log.Println("Answer was broadcasted")
	}

}

func handleMineAnswer(n *Node, answerMsg income) {
	peerHex := ParseHex256(answerMsg.Signal.Sender)
	log.Println("Received aswer from:", peerHex)

	n.waitAnswersMu.Lock()
	ans, ok := n.waitAnswers[peerHex]
	n.waitAnswersMu.Unlock()
	if !ok {
		return
	}

	decryptedPayload, err := crypt.DecryptMessage(answerMsg.Signal.Payload, n.ecdhPrivate, ans.ecdhPublic)
	if err != nil {
		return
	}
	var ansSDP webrtc.SessionDescription
	err = json.Unmarshal(decryptedPayload, &ansSDP)
	if err != nil {
		return
	}

	ans.dc.OnOpen(func() {
		n.waitAnswersMu.Lock()
		delete(n.waitAnswers, peerHex)
		n.waitAnswersMu.Unlock()
		inbox := make(chan []byte)

		pong := make(chan struct{})
		ans.dc.OnClose(func() {
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

		ans.dc.OnMessage(func(msg webrtc.DataChannelMessage) {
			if bytes.Equal(msg.Data, pingSignal) {
				log.Println("RTC Ping")
				ans.dc.Send(pongSignal)
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
			ans.ecdhPublic,
			inbox,
			true)

		go func() {
			defer func() {
				log.Println("RTC outbox closed")
				ans.pc.Close()
				ans.dc.Close()
			}()

			pingTicker := time.NewTicker(pingPeriod)
			for {
				select {
				case <-pingTicker.C:
					ans.dc.Send(pingSignal)
				case data, work := <-outbox:
					if !work {
						return
					}

					ans.dc.Send(data)
				}
			}
		}()

	})

	ans.pc.SetRemoteDescription(ansSDP)
}
