package crypt

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
)

func EncryptPeerMessage(
	payload []byte,
	senderECDH *ecdh.PrivateKey,
	senderEDPrivate ed25519.PrivateKey,
	senderEDPub ed25519.PublicKey,
	receiverECDH *ecdh.PublicKey,
) ([]byte, error) {
	aesKey := make([]byte, 32)
	if _, err := rand.Read(aesKey); err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonceAES := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonceAES); err != nil {
		return nil, err
	}
	encryptedPayload := gcm.Seal(nonceAES, nonceAES, payload, nil)

	sharedSecret, err := senderECDH.ECDH(receiverECDH)
	if err != nil {
		return nil, err
	}
	sharedKey := sha256.Sum256(sharedSecret)
	keyBlock, err := aes.NewCipher(sharedKey[:])
	if err != nil {
		return nil, err
	}
	keyGCM, err := cipher.NewGCM(keyBlock)
	if err != nil {
		return nil, err
	}
	keyNonce := make([]byte, keyGCM.NonceSize())
	if _, err := rand.Read(keyNonce); err != nil {
		return nil, err
	}
	encryptedAESKey := keyGCM.Seal(keyNonce, keyNonce, aesKey, nil)

	data := append(senderEDPub, encryptedAESKey...)
	data = append(data, encryptedPayload...)
	signature := ed25519.Sign(senderEDPrivate, data)

	return append(data, signature...), nil
}

func DecryptPeerMessage(data []byte, receiverECDH *ecdh.PrivateKey, senderECPub *ecdh.PublicKey) ([]byte, error) {
	if len(data) < 32+64 {
		return nil, fmt.Errorf("data too short: missing senderEdPub or signature")
	}

	senderEdPub := ed25519.PublicKey(data[:32])
	payloadAndKey := data[:len(data)-64]
	signature := data[len(data)-64:]

	if !ed25519.Verify(senderEdPub, payloadAndKey, signature) {
		return nil, fmt.Errorf("invalid signature")
	}

	sharedSecret, err := receiverECDH.ECDH(senderECPub)
	if err != nil {
		return nil, err
	}
	sharedKey := sha256.Sum256(sharedSecret)
	keyBlock, err := aes.NewCipher(sharedKey[:])
	if err != nil {
		return nil, err
	}
	keyGCM, err := cipher.NewGCM(keyBlock)
	if err != nil {
		return nil, err
	}
	nonceSize := keyGCM.NonceSize()
	expectedKeyLen := nonceSize + 32 + 16
	if len(data) < 32+expectedKeyLen+64 {
		return nil, fmt.Errorf("data too short for encrypted key")
	}

	encryptedAESKey := data[32 : 32+expectedKeyLen]
	aesKey, err := keyGCM.Open(nil, encryptedAESKey[:nonceSize], encryptedAESKey[nonceSize:], nil)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt AES key: %v", err)
	}

	encryptedPayload := data[32+expectedKeyLen : len(data)-64]
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(encryptedPayload) < gcm.NonceSize() {
		return nil, fmt.Errorf("payload too short")
	}
	nonce := encryptedPayload[:gcm.NonceSize()]
	ciphertext := encryptedPayload[gcm.NonceSize():]
	decryptedPayload, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt payload: %v", err)
	}

	return decryptedPayload, nil
}
