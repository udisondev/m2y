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
	"m2y/config"
	"m2y/pkg/crypt"
	"m2y/pkg/logger"
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
		listenAddr    *net.TCPAddr
		bufPool       *sync.Pool
		noncePool     *sync.Pool
		challangePool *sync.Pool
		peerPool      *sync.Pool
		mpeerMu       *sync.RWMutex
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

func New(conf config.Config) *Node {
	bufPool := sync.Pool{}
	bufPool.New = func() any { return make([]byte, 0, 1024) }

	peerPool := sync.Pool{}
	for range maxPeersCount {
		peerPool.Put(&peer{})
	}

	n := Node{
		bufPool:  &bufPool,
		peerPool: &peerPool,
	}

	if conf.ListenAddr != "" {
		addr, err := net.ResolveTCPAddr("tcp", conf.ListenAddr)
		if err != nil {
			panic(fmt.Errorf("could not parse listen addr as TCPAddr: %v", err))
		}
		n.listenAddr = addr

		n.peerPool.New = func() any { return &peer{} }

		n.noncePool = &sync.Pool{}
		n.noncePool.New = func() any { return make([]byte, 0, 12) }

		n.challangePool = &sync.Pool{}
		n.challangePool.New = func() any { return make([]byte, 0, 32) }
	}

	return &n
}

func (n *Node) Run(entrypoint *net.TCPAddr) {
	if entrypoint == nil {
		panic("entrypoint is nil")
	}

	err := n.Connect(entrypoint)
	if err != nil {
		panic(fmt.Errorf("could not connect to the %+v: %v", entrypoint, err))
	}

	if n.listenAddr != nil {
		go n.listen(n.listenAddr)
	}
}

func (n *Node) Connect(addr *net.TCPAddr) error {
	header := "Node.Connect"
	conn, err := net.DialTCP("tcp", nil, addr)
	if err != nil {
		return err
	}

	err = conn.SetReadBuffer(1024)
	if err != nil {
		return fmt.Errorf("set read buffer: %v", err)
	}

	pubKeyBuf := n.bufPool.Get().(*bytes.Buffer)
	pubKeyBuf.Reset()
	defer n.bufPool.Put(pubKeyBuf)

	for read := 0; read < pubKeyLenth; {
		n, err := conn.Read(pubKeyBuf.Bytes())
		if errors.Is(err, io.EOF) && read < pubKeyLenth {
			return errors.New("short pub key")
		}

		if errors.Is(err, io.EOF) {
			break
		}

		if err != nil {
			return fmt.Errorf("read pub key: %w", err)
		}
		read += n
	}
	logger.Debugf(header, "Received entrypoint public key...")

	pubKey, err := ecdh.P256().NewPublicKey(pubKeyBuf.Bytes())
	if err != nil {
		return fmt.Errorf("parse pub key: %w", err)
	}
	logger.Debugf(header, "Public key parsed...")

	for written := 0; written < pubKeyLenth; {
		n, err := conn.Write(n.ecdh.PublicKey().Bytes()[written:])
		if err != nil {
			return fmt.Errorf("send pub key: %w", err)
		}
		written += n
	}
	logger.Debugf(header, "My public key was sent...")

	var mlen uint32
	err = binary.Read(conn, binary.BigEndian, &mlen)
	if err != nil {
		return fmt.Errorf("read challange length: %w", err)
	}

	challenge := n.challangePool.Get().([]byte)
	defer n.challangePool.Put(challenge)

	for read := 0; read < int(mlen); {
		n, err := conn.Read(challenge)
		if errors.Is(err, io.EOF) && read < int(mlen) {
			return errors.New("short challange")
		}

		if errors.Is(err, io.EOF) {
			break
		}

		if err != nil {
			return fmt.Errorf("read challange: %w", err)
		}

		read += n
	}
	logger.Debugf(header, "Challange read...")

	err = n.solveChallange(challenge, pubKey, conn)
	if err != nil {
		return fmt.Errorf("solving challange: %w", err)
	}
	logger.Debugf(header, "Challange solved...")

	init, _ := n.bookPeer()
	if init == nil {
		return errors.New("has no free slot")
	}

	conn.SetReadDeadline(time.Time{})
	conn.SetWriteDeadline(time.Time{})

	init(true, true, pubKey, conn)
	logger.Debugf(header, "Connected to entrypoint!")

	return nil
}

func (n *Node) bookPeer() (init func(
	isTrusted bool,
	isOnboarded bool,
	pubKey *ecdh.PublicKey,
	rw io.ReadWriteCloser,
), free func()) {
	header := "Node.bookPeer"
	peer := n.peerPool.Get().(*peer)
	if peer == nil {
		logger.Warnf(header, "Has no free peer")
		return nil, nil
	}

	free = sync.OnceFunc(func() {
		header := header + ".free"
		logger.Debugf(header, "peer=%s", peer.hash())
		peer.reset()
		n.peerPool.Put(peer)
	})

	logger.Debugf(header, "Ready!")

	return func(isTnusted bool, isOnboarded bool, pubKey *ecdh.PublicKey, rw io.ReadWriteCloser) {
		peer.pubKey = pubKey
		if isTnusted {
			peer.state.Store(trusted)
		} else {
			peer.state.Store(active)
		}
		peer.w = rw

		n.mpeerMu.Lock()
		n.mpeer[peer.hash()] = peer
		n.mpeerMu.Unlock()

		peer.disconnect = sync.OnceFunc(func() {
			header := "Disconnected"
			logger.Debugf(header, "peer=%s", peer.hash())

			n.mpeerMu.Lock()
			delete(n.mpeer, peer.hash())
			n.mpeerMu.Unlock()

			rw.Close()
			free()
		})

		header := header + ".init"

		go func() {
			header := fmt.Sprintf("Peer=%s", peer.hash())

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
	header := "Node.handleConn"
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

	for written := 0; written < pubKeyLenth; {
		n, err := conn.Write(n.ecdh.PublicKey().Bytes()[written:])
		if errors.Is(err, io.EOF) {
			break
		}

		if err != nil {
			logger.Errorf(header, "Error write my public key: %v", err)
			return
		}
		written += n
	}
	logger.Debugf(header, "My public key was sent...")

	pubKeyBuf := n.bufPool.Get().(*bytes.Buffer)
	pubKeyBuf.Reset()
	defer n.bufPool.Put(pubKeyBuf)

	err = conn.SetReadDeadline(time.Now().Add(time.Second))
	if err != nil {
		logger.Errorf(header, "Error set deadline to reading guest's public key: %v", err)
		return
	}

	for read := 0; read < pubKeyLenth; {
		n, err := conn.Read(pubKeyBuf.Bytes())
		if errors.Is(err, io.EOF) && read < pubKeyLenth {
			logger.Errorf(header, "Unexpected EOF. Receiving public key")
			return
		}

		if errors.Is(err, io.EOF) {
			break
		}

		if err != nil {
			logger.Errorf(header, "Error read guest's public key: %v", err)
			return
		}
		read += n
	}

	logger.Debugf(header, "Received new connectrion's public key...")

	pubKey, err := ecdh.P256().NewPublicKey(pubKeyBuf.Bytes())
	if err != nil {
		logger.Errorf(header, "Error parse guest's public key: %v", err)
		return
	}
	logger.Debugf(header, "Public key parsed...")

	challenge := n.challangePool.Get().([]byte)
	defer n.challangePool.Put(challenge)

	for read := 0; read < challangeLength; {
		n, err := rand.Read(challenge)
		if errors.Is(err, io.EOF) && read < challangeLength {
			logger.Errorf(header, "Unexpected EOF. Generating challange")
			return
		}

		if errors.Is(err, io.EOF) {
			break
		}

		if err != nil {
			logger.Errorf(header, "Error generate challange: %v", err)
			return
		}

		read += n
	}
	logger.Debugf(header, "Challange generated...")

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
	logger.Debugf(header, "Challange sent...")

	solvedBuf := n.bufPool.Get().(*bytes.Buffer)
	solvedBuf.Reset()
	defer n.bufPool.Put(solvedBuf)

	err = conn.SetReadDeadline(time.Now().Add(time.Second))
	if err != nil {
		logger.Errorf(header, "Error set deadline to reading challange solving: %v", err)
		return
	}

	var mlen uint32
	err = binary.Read(conn, binary.BigEndian, &mlen)
	if err != nil {
		logger.Errorf(header, "Error read solved challange message length: %v", err)
		return
	}

	for read := 0; read < int(mlen); {
		n, err := conn.Read(solvedBuf.Bytes())
		if errors.Is(err, io.EOF) && read < int(mlen) {
			logger.Errorf(header, "Unexpected EOF. Reading challange solving")
			return
		}

		if errors.Is(err, io.EOF) {
			break
		}

		if err != nil {
			logger.Errorf(header, "Error read challange solving: %v", err)
			return
		}

		read += n
	}
	logger.Debugf(header, "Received challange solving...")

	err = n.checkChallenge(challenge, solvedBuf.Bytes(), pubKey)
	if errors.Is(err, errChallengeSolving) {
		logger.Warnf(header, "challange failed!")
		return
	}

	logger.Debugf(header, "Challange successfuly passed...")

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

	n.mpeerMu.RLock()
	peersCount := len(n.mpeer)
	n.mpeerMu.RUnlock()

	needOnboard := peersCount > 0
	init(false, needOnboard, pubKey, conn)

	logger.Debugf(header, "New conn onboarded!")
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

	encrypted := gcm.Seal(nonce, nonce, challenge, nil)
	err = binary.Write(w, binary.BigEndian, uint32(len(encrypted)))
	if err != nil {
		return fmt.Errorf("send encrypted length: %w", err)
	}

	for written := 0; written < len(encrypted); {
		n, err := w.Write(encrypted[written:])
		if err != nil {
			return fmt.Errorf("send challenge: %w", err)
		}
		written += n
	}

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

func (n *Node) solveChallange(ciphertext []byte, verifierECPub *ecdh.PublicKey, w io.Writer) error {
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
	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]

	decrypted, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return fmt.Errorf("decrypt challange: %w", err)
	}

	for written := 0; written < len(decrypted); {
		n, err := w.Write(decrypted[written:])
		if err != nil {
			return fmt.Errorf("send solved challange: %w", err)
		}
		written += n
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
