package keys

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha512"
	"log"
)

// What format should i use here?
const (
	Xsecp521r1pKey    KeyType = "secp521r1"
	Xsecp521r1pKeyHRP string  = "kbx"
)

type (
	SecpMessage string
)

func NewMSG(msg string) SecpMessage {
	return SecpMessage(msg)
}

func (m SecpMessage) bytes() []byte {
	return []byte(m)
}

func (m SecpMessage) digest() [sha512.Size]byte {
	return sha512.Sum512(m.bytes())
}

func (m SecpMessage) sign(sk *ecdsa.PrivateKey) []byte {
	// digest the message
	dgst := m.digest()

	// Sign
	signedMsg, err := sk.Sign(rand.Reader, dgst[:], crypto.SHA512)
	if err != nil {
		log.Fatalf("failed to sign\n\tmessage m: %+v\n\tgot err: %+v", m, err)
	}

	// Verify
	if !ecdsa.VerifyASN1(&sk.PublicKey, dgst[:], signedMsg) {
		log.Fatalf("failed to verifyANS1\n\tmessage m: %+v\n\tdigest d: %+v", signedMsg, dgst)
	}

	log.Printf("ANS1 signature verified %v", signedMsg)
	return signedMsg
}
