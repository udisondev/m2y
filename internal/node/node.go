package node

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ed25519"
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
		listenAddr    string
		entrypoint    string
		bufPool       *sync.Pool
		pubKeyPool    *sync.Pool
		noncePool     *sync.Pool
		challangePool *sync.Pool
		peerPool      *sync.Pool
		mpeerMu       sync.RWMutex
		mpeer         map[string]*peer
		*dispatcher
		*cache
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
	logPref := "node.New"
	bufPool := sync.Pool{
		New: func() any { return make([]byte, 1024) },
	}
	logger.Debugf(logPref, "bufPool initialized")

	peerPool := sync.Pool{}
	for range maxPeersCount {
		peerPool.Put(&peer{})
	}
	logger.Debugf(logPref, "%d peers placed into peerBoof", maxPeersCount)

	key, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		panic(fmt.Errorf("generate prinvate ecdh: %v", err))
	}

	publicSign, privateSign, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		panic(fmt.Errorf("generate sign pair: %v", err))
	}

	n := Node{
		bufPool: &bufPool,
		pubKeyPool: &sync.Pool{
			New: func() any { return make([]byte, 65) },
		},
		peerPool: &peerPool,
		dispatcher: &dispatcher{
			ecdh:        key,
			publicSign:  publicSign,
			privateSign: privateSign,
		},
		challangePool: &sync.Pool{
			New: func() any { return make([]byte, 32) },
		},
		cache: newCache(),
		mpeer: make(map[string]*peer, maxPeersCount),
	}

	if conf.Entrypoint != "" {
		n.entrypoint = conf.Entrypoint
	}

	if conf.ListenAddr != "" {
		logger.Debugf(logPref, "I'am an entrypoint and going to listen: %s", conf.ListenAddr)
		n.listenAddr = conf.ListenAddr

		n.peerPool.New = func() any { return &peer{} }

		n.noncePool = &sync.Pool{
			New: func() any { return make([]byte, 12) },
		}
	}

	logger.Debugf(logPref, "Node configured!")
	return &n
}

func (n *Node) Run() {
	logPref := "Node.Run"
	if n.entrypoint != "" {
		logger.Debugf(logPref, "Entrypoint is not nil, going to connect to: %s", n.entrypoint)
		go func() {
			err := n.Connect(n.entrypoint)
			if err != nil {
				panic(fmt.Errorf("could not connect to the %s: %v", n.entrypoint, err))
			}
		}()
	}

	if n.listenAddr != "" {
		logger.Debugf(logPref, "Listen address is not nil, going to listen: %s", n.listenAddr)
		go n.listen(n.listenAddr)
	}
}

func (n *Node) Connect(addr string) error {
	logPref := "Node.Connect"
	logger.Debugf(logPref, "Going to dial TCP...")
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		return err
	}

	defer func() {
		if err != nil {
			conn.Close()
		}
	}()

	logger.Debugf(logPref, "Connection established...")

	logger.Debugf(logPref, "Reading entrypoint's public key...")
	pubKeyBuf := n.pubKeyPool.Get().([]byte)
	defer n.pubKeyPool.Put(pubKeyBuf)

	for read := 0; read < pubKeyLenth; {
		n, err := conn.Read(pubKeyBuf[read:])
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
		//	logger.Debugf(logPref, "%d bytes read...", read)
	}
	logger.Debugf(logPref, "Received entrypoint public key...")

	pubKey, err := ecdh.P256().NewPublicKey(pubKeyBuf)
	if err != nil {
		return fmt.Errorf("parse pub key: %w", err)
	}
	logger.Debugf(logPref, "Public key parsed...")

	for written := 0; written < pubKeyLenth; {
		n, err := conn.Write(n.ecdh.PublicKey().Bytes()[written:])
		if err != nil {
			return fmt.Errorf("send pub key: %w", err)
		}
		written += n
	}
	logger.Debugf(logPref, "My public key was sent...")

	var mlen uint32
	err = binary.Read(conn, binary.BigEndian, &mlen)
	if err != nil {
		return fmt.Errorf("read challange length: %w", err)
	}

	logger.Debugf(logPref, "Recieved pack with length: %d", mlen)

	challangeBuf := n.buf()
	defer n.putBuf(challangeBuf)

	for read := 0; read < int(mlen); {
		n, err := conn.Read(challangeBuf[read:])
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
	logger.Debugf(logPref, "Challange read...")

	err = n.solveChallange(challangeBuf[:mlen], pubKey, conn)
	if err != nil {
		return fmt.Errorf("solving challange: %w", err)
	}
	logger.Debugf(logPref, "Challange solved...")

	init, _ := n.bookPeer()
	if init == nil {
		return errors.New("has no free slot")
	}

	conn.SetReadDeadline(time.Time{})
	conn.SetWriteDeadline(time.Time{})

	init(true, true, pubKey, conn)
	logger.Debugf(logPref, "Connected to entrypoint!")

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

			for {
				dectypted, err := n.decrypt(pubKey, rw)
				if err != nil {
					return
				}
				logger.Debugf(header, "Decrypted...")

				if !n.filter(dectypted) {
					continue
				}

				logger.Debugf(header, "Filtered...")

				a, b := n.dispatch(dectypted)

				n.put(hex.EncodeToString(signal(b).nonce()))
				switch a {
				case disconnect:
					return
				case direct:
					err = n.encrypt(pubKey, b, rw)
					if err != nil {
						return
					}
				case broadcast:
					for _, p := range n.mpeer {
						if p.state.Load() < trusted {
							continue
						}

						err = n.encrypt(p.pubKey, b, p.w)
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

func (n *Node) encrypt(pubKey *ecdh.PublicKey, b []byte, w io.Writer) error {
	encrypted, err := crypt.EncryptPeerMessage(
		b,
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

func (n *Node) filter(b []byte) bool {
	return n.putIfAbsent(hex.EncodeToString(signal(b).nonce()))
}

func (n *Node) decrypt(pubKey *ecdh.PublicKey, in io.Reader) ([]byte, error) {
	buf := n.buf()
	defer n.putBuf(buf)

	var mlen uint32
	err := binary.Read(in, binary.BigEndian, &mlen)
	if err != nil {
		return nil, err
	}

	for read := 0; read < int(mlen); {
		n, err := in.Read(buf[read:])
		if errors.Is(err, io.EOF) && read == int(mlen) {
			break
		}
		if err != nil {
			return nil, err
		}

		read += int(n)
	}

	decrypted, err := crypt.DecryptPeerMessage(buf, n.ecdh, pubKey)
	if err != nil {
		return nil, err
	}

	return decrypted, nil
}

func (n *Node) listen(addr string) error {
	logPref := "Node.listen"
	l, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}

	defer l.Close()

	for {
		conn, err := l.Accept()
		if err != nil {
			logger.Errorf(logPref, "Error accept TCP: %v", err)
			continue
		}

		go n.handleConn(conn)
	}
}

func (n *Node) handleConn(conn net.Conn) {
	logPref := "Node.handleConn"

	err := conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
	if err != nil {
		logger.Errorf(logPref, "Error set write deadline", err)
		return
	}

	defer func() {
		if err != nil {
			conn.Close()
		}
	}()

	err = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	if err != nil {
		logger.Errorf(logPref, "Error set read deadline", err)
		return
	}

	for written := 0; written < pubKeyLenth; {
		n, err := conn.Write(n.ecdh.PublicKey().Bytes()[written:])
		if err != nil {
			logger.Errorf(logPref, "Error write my public key: %v", err)
			return
		}
		written += n
		logger.Debugf(logPref, "%d bytes of public key was sent", written)
	}
	logger.Debugf(logPref, "My public key was sent...")

	pubKeyBuf := n.pubKeyPool.Get().([]byte)
	defer n.pubKeyPool.Put(pubKeyBuf)

	for read := 0; read < pubKeyLenth; {
		n, err := conn.Read(pubKeyBuf[read:])
		if errors.Is(err, io.EOF) && read < pubKeyLenth {
			logger.Errorf(logPref, "Error reading new connection's public key. Too short")
			return
		}
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			logger.Errorf(logPref, "Error reading new connection's public key: %v", err)
			return
		}
		read += n
	}

	logger.Debugf(logPref, "Received new connectrion's public key...")

	pubKey, err := ecdh.P256().NewPublicKey(pubKeyBuf)
	if err != nil {
		logger.Errorf(logPref, "Error parse guest's public key: %v", err)
		return
	}
	logger.Debugf(logPref, "Public key parsed...")

	challenge := n.challangePool.Get().([]byte)
	defer n.challangePool.Put(challenge)

	for read := 0; read < challangeLength; {
		n, err := rand.Read(challenge)
		if errors.Is(err, io.EOF) && read < challangeLength {
			logger.Errorf(logPref, "Unexpected EOF. Generating challange")
			return
		}

		if errors.Is(err, io.EOF) {
			break
		}

		if err != nil {
			logger.Errorf(logPref, "Error generate challange: %v", err)
			return
		}

		read += n
	}
	logger.Debugf(logPref, "Challange generated...")

	err = n.encryptAndWriteChallenge(challenge, pubKey, conn)
	if err != nil {
		logger.Errorf(logPref, "Error send challange: %v", err)
		return
	}
	logger.Debugf(logPref, "Challange sent...")

	var mlen uint32
	err = binary.Read(conn, binary.BigEndian, &mlen)
	if err != nil {
		logger.Errorf(logPref, "Error read solved challange message length: %v", err)
		return
	}

	logger.Debugf(logPref, "Received solved challange pack with length: %d", mlen)

	solvedBuf := n.buf()
	defer n.putBuf(solvedBuf)

	for read := 0; read < int(mlen); {
		n, err := conn.Read(solvedBuf[read:])
		if errors.Is(err, io.EOF) && read < int(mlen) {
			logger.Errorf(logPref, "Unexpected EOF. Reading challange solving")
			return
		}

		if errors.Is(err, io.EOF) {
			break
		}

		if err != nil {
			logger.Errorf(logPref, "Error read challange solving: %v", err)
			return
		}

		read += n
	}
	logger.Debugf(logPref, "Received challange solving...")

	if !n.checkChallenge(challenge, solvedBuf[:mlen]) {
		return
	}

	logger.Debugf(logPref, "Challange successfuly passed...")

	if err != nil {
		logger.Errorf(logPref, "Error check challange solving: %v", err)
		return
	}

	init, _ := n.bookPeer()
	if init == nil {
		logger.Errorf(logPref, "Error set read buffer: %v", err)
		return
	}

	conn.SetReadDeadline(time.Time{})
	conn.SetWriteDeadline(time.Time{})

	n.mpeerMu.RLock()
	peersCount := len(n.mpeer)
	n.mpeerMu.RUnlock()

	needOnboard := peersCount > 0
	init(false, needOnboard, pubKey, conn)

	logger.Debugf(logPref, "New conn onboarded!")
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

func (n *Node) checkChallenge(challenge []byte, solved []byte) bool {
	return bytes.Equal(challenge, solved)
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

	err = binary.Write(w, binary.BigEndian, uint32(len(decrypted)))
	if err != nil {
		return fmt.Errorf("send solved challange length: %w", err)
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

func (n *Node) buf() []byte {
	bts := n.bufPool.Get().([]byte)
	for i := range bts {
		bts[i] = 0
	}
	return bts
}

func (n *Node) putBuf(b []byte) {
	n.bufPool.Put(b)
}
