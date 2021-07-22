package keys

import (
	"crypto"
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

func (m SecpMessage) sign(kp KP) []byte {
	dgst := m.digest()
	signedMsg, err := kp.sk.Sign(rand.Reader, dgst[:], crypto.SHA512)
	if err != nil {
		log.Fatalf("failed to sign\n\tmessage m: %+v\n\tgot err: %+v", m, err)
	}
	log.Printf("%+v", signedMsg)
	return signedMsg
}
