package node

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"m2y/pkg/crypt"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

type (
	peer struct {
		state      atomic.Uint32
		pubKey     *ecdh.PublicKey
		w          io.Writer
		disconnect func()
	}

	Node struct {
		bufPool       sync.Pool
		noncePool     sync.Pool
		challengePool sync.Pool
		peerPool      sync.Pool
		mpeer         map[string]*peer
		dispatcher
		cache
	}
)

var errChallengeSolving = errors.New("challange failed")
var errDuplicated = errors.New("duplicated")

const (
	inactive = 0 << iota
	active
	trusted
)

const (
	broadcast  uint8 = 0x00
	direct           = 0x01
	disconnect       = 0xFF
)

func New() *Node {
	n := Node{}

	return &n
}

func (n *Node) bookPeer() (init func(
	pubKey *ecdh.PublicKey,
	rw io.ReadWriteCloser,
), free func()) {
	header := logger.InitHeader("Node.bookPeer")
	peer := n.peerPool.Get().(*peer)
	if peer == nil {
		logger.Warnf(header, "Has no free peer")
		return nil, nil
	}

	free = sync.OnceFunc(func() {
		header := logger.ExtendHeader(header, "Free")
		logger.Debugf(header, "peer=%s", peer.hash())
		peer.reset()
		n.peerPool.Put(peer)
	})

	logger.Debugf(header, "Ready!")

	return func(pubKey *ecdh.PublicKey, rw io.ReadWriteCloser) {
		peer.pubKey = pubKey
		peer.state.Store(active)
		peer.w = rw
		peer.disconnect = sync.OnceFunc(func() {
			logger.Debugf(logger.InitHeader("Disconnected"), "peer=%s", peer.hash())
			rw.Close()
			free()
		})

		header := logger.ExtendHeader(header, "Init")

		go func() {
			header = logger.InitHeader("Peer=%s", peer.hash())

			decryptedBuf := n.bufPool.Get().(*bytes.Buffer)
			filteredBuf := n.bufPool.Get().(*bytes.Buffer)
			dispatchedBuf := n.bufPool.Get().(*bytes.Buffer)
			callbackBuf := n.bufPool.Get().(*bytes.Buffer)

			defer n.bufPool.Put(decryptedBuf)
			defer n.bufPool.Put(filteredBuf)
			defer n.bufPool.Put(dispatchedBuf)
			defer n.bufPool.Put(callbackBuf)

			for {
				decryptedBuf.Reset()
				filteredBuf.Reset()
				dispatchedBuf.Reset()
				callbackBuf.Reset()

				err := n.decrypt(pubKey, rw, decryptedBuf)
				if err != nil {
					return
				}
				logger.Debugf(header, "Decrypted...")

				err = n.filter(decryptedBuf, filteredBuf)
				if errors.Is(err, errDuplicated) {
					continue
				}
				if err != nil {
					return
				}
				logger.Debugf(header, "Filtered...")

				n.dispatch(filteredBuf, dispatchedBuf)

				_, err = callbackBuf.ReadFrom(dispatchedBuf)
				if err != nil {
					return
				}

				a, _ := callbackBuf.ReadByte()
				n.put(hex.EncodeToString(signal(callbackBuf.Bytes()).nonce()))
				switch a {
				case disconnect:
					return
				case direct:
					err = n.encrypt(pubKey, callbackBuf, rw)
					if err != nil {
						return
					}
				case broadcast:
					for _, p := range n.mpeer {
						if p.state.Load() < trusted {
							continue
						}

						buf := n.bufPool.Get().(*bytes.Buffer)
						buf.Reset()
						err = n.encrypt(p.pubKey, buf, p.w)
						n.bufPool.Put(buf)
						if err != nil {
							p.disconnect()
							continue
						}
					}
				}
			}
		}()

		logger.Debugf(header, "Configured! Peer=%s", peer.hash())
	}, free
}

func (n *Node) encrypt(pubKey *ecdh.PublicKey, r io.Reader, w io.Writer) error {
	buf := n.bufPool.Get().(*bytes.Buffer)
	defer n.bufPool.Put(buf)

	buf.Reset()
	_, err := buf.ReadFrom(r)
	if err != nil {
		return err
	}

	encrypted, err := crypt.EncryptPeerMessage(
		buf.Bytes(),
		n.ecdh,
		n.privateSign,
		n.publicSign,
		pubKey,
	)
	if err != nil {
		return err
	}

	mlen := len(encrypted)
	binary.Write(w, binary.BigEndian, uint32(mlen))
	for written := 0; written < mlen; {
		n, err := w.Write(encrypted)
		if err != nil {
			return err
		}
		written += n
	}

	return nil
}

func (n *Node) filter(in *bytes.Buffer, out *bytes.Buffer) error {
	if n.putIfAbsent(hex.EncodeToString(signal(in.Bytes()).nonce())) {
		return errDuplicated
	}

	out.Write(in.Bytes())

	return nil
}

func (n *Node) decrypt(pubKey *ecdh.PublicKey, in io.Reader, out *bytes.Buffer) error {
	buf := n.bufPool.Get().(*bytes.Buffer)
	buf.Reset()
	defer n.bufPool.Put(buf)

	var mlen uint32
	err := binary.Read(in, binary.BigEndian, &mlen)
	if err != nil {
		return err
	}

	for read := 0; read < int(mlen); {
		n, err := buf.ReadFrom(in)
		if errors.Is(err, io.EOF) && read == int(mlen) {
			break
		}
		if err != nil {
			return err
		}

		read += int(n)
	}

	decrypted, err := crypt.DecryptPeerMessage(buf.Bytes(), n.ecdh, pubKey)
	if err != nil {
		return err
	}

	out.Write(decrypted)

	return nil
}

func (n *Node) listen(addr *net.TCPAddr) error {
	tcpListener, err := net.ListenTCP("tcp", addr)
	if err != nil {
		return err
	}

	for {
		conn, err := tcpListener.AcceptTCP()
		if err != nil {
			continue
		}

		go n.handleConn(conn)
	}
}

func (n *Node) handleConn(conn *net.TCPConn) {
	header := logger.InitHeader("Node.handleConn")
	err := conn.SetReadBuffer(1024)
	if err != nil {
		logger.Errorf(header, "Error set read buffer: %v", err)
		return
	}

	err = conn.SetWriteDeadline(time.Now().Add(time.Second))
	if err != nil {
		logger.Errorf(header, "Error set deadline to sending my public key: %v", err)
		return
	}

	_, err = conn.Write(n.ecdh.PublicKey().Bytes())
	if err != nil {
		logger.Errorf(header, "Error write my public key: %v", err)
		return
	}

	pubKeyBuf := n.bufPool.Get().(*bytes.Buffer)
	pubKeyBuf.Reset()
	defer n.bufPool.Put(pubKeyBuf)

	err = conn.SetReadDeadline(time.Now().Add(time.Second))
	if err != nil {
		logger.Errorf(header, "Error set deadline to reading guest's public key: %v", err)
		return
	}

	_, err = pubKeyBuf.ReadFrom(conn)
	if err != nil {
		logger.Errorf(header, "Error read guest's public key: %v", err)
		return
	}

	pubKey, err := ecdh.P256().NewPublicKey(pubKeyBuf.Bytes())
	if err != nil {
		logger.Errorf(header, "Error parse guest's public key: %v", err)
		return
	}

	challenge := n.challengePool.Get().([]byte)
	defer n.challengePool.Put(challenge)

	_, err = rand.Read(challenge)
	if err != nil {
		logger.Errorf(header, "Error generate challange: %v", err)
		return
	}

	err = conn.SetWriteDeadline(time.Now().Add(time.Second))
	if err != nil {
		logger.Errorf(header, "Error set deadline to sending challange: %v", err)
		return
	}

	err = n.encryptAndWriteChallenge(challenge, pubKey, conn)
	if err != nil {
		logger.Errorf(header, "Error send challange: %v", err)
		return
	}

	solvedBuf := n.bufPool.Get().(*bytes.Buffer)
	solvedBuf.Reset()
	defer n.bufPool.Put(solvedBuf)

	err = conn.SetReadDeadline(time.Now().Add(time.Second))
	if err != nil {
		logger.Errorf(header, "Error set deadline to reading challange solving: %v", err)
		return
	}

	_, err = solvedBuf.ReadFrom(conn)
	if err != nil {
		logger.Errorf(header, "Error read challange solving: %v", err)
		return
	}

	err = n.checkChallenge(challenge, solvedBuf.Bytes(), pubKey)
	if errors.Is(err, errChallengeSolving) {
		logger.Warnf(header, "challange failed!")
		return
	}

	if err != nil {
		logger.Errorf(header, "Error check challange solving: %v", err)
		return
	}

	init, _ := n.bookPeer()
	if init == nil {
		logger.Errorf(header, "Error set read buffer: %v", err)
		return
	}

	conn.SetReadDeadline(time.Time{})
	conn.SetWriteDeadline(time.Time{})

	init(pubKey, conn)
}

func (n *Node) encryptAndWriteChallenge(challenge []byte, verifierECPub *ecdh.PublicKey, w io.Writer) error {
	sharedSecret, err := n.ecdh.ECDH(verifierECPub)
	if err != nil {
		return fmt.Errorf("generate sharred secret: %w", err)
	}
	sharedKey := sha256.Sum256(sharedSecret)

	block, err := aes.NewCipher(sharedKey[:])
	if err != nil {
		return fmt.Errorf("generate new cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return fmt.Errorf("generate new gsm: %w", err)
	}
	nonce := n.noncePool.Get().([]byte)
	defer n.noncePool.Put(nonce)

	rand.Read(nonce)

	_, err = w.Write(gcm.Seal(nonce, nonce, challenge, nil))
	return err
}

func (n *Node) checkChallenge(challenge []byte, enctyptedSolved []byte, verifierECPub *ecdh.PublicKey) error {
	sharedSecret, err := n.ecdh.ECDH(verifierECPub)
	if err != nil {
		return fmt.Errorf("generate sharred secret: %w", err)
	}

	sharedKey := sha256.Sum256(sharedSecret)

	block, err := aes.NewCipher(sharedKey[:])
	if err != nil {
		return fmt.Errorf("generate new cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return fmt.Errorf("generate new gsm: %w", err)
	}
	nonceSize := gcm.NonceSize()
	nonce, ciphertext := enctyptedSolved[:nonceSize], enctyptedSolved[nonceSize:]

	decrypted, err := gcm.Open(nil, nonce, ciphertext, nil)
	if !bytes.Equal(challenge, decrypted) {
		return errChallengeSolving
	}

	return nil
}

func (p *peer) reset() {
	p.state.Store(inactive)
	p.pubKey = nil
	p.w = nil
	p.disconnect = nil
}

func (p *peer) hash() string {
	sum := sha256.Sum256(p.pubKey.Bytes())
	return hex.EncodeToString(sum[:])
}
