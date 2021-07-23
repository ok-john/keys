package keys

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha512"
	"log"
	"math/big"
)

// What format should i use here?
const (
	Xsecp521r1pKey    KeyType = "secp521r1"
	Xsecp521r1pKeyHRP string  = "kbx"
)

type (
	SecpMessage string
)

func newEcSk(ctx context.Context) *ecdsa.PrivateKey {
	defer ctx.Done()
	curve := elliptic.P521()

	pk, x, y, err := elliptic.GenerateKey(curve, rand.Reader)
	if err != nil {
		panic(err)
	}

	pubk := ecdsa.PublicKey{
		Curve: curve,
		X:     x,
		Y:     y,
	}

	return &ecdsa.PrivateKey{
		PublicKey: pubk,
		D:         big.NewInt(5096).SetBytes(pk),
	}
}

func (m SecpMessage) bytes() []byte {
	return []byte(m)
}

func (m SecpMessage) digest() [sha512.Size]byte {
	return sha512.Sum512(m.bytes())
}

func (m SecpMessage) sign(sk *ecdsa.PrivateKey, digest []byte) []byte {
	// Sign
	signedMsg, err := sk.Sign(rand.Reader, digest, crypto.SHA512)
	if err != nil {
		log.Fatalf("failed to sign\n\tmessage m: %+v\n\tgot err: %+v", m, err)
	}
	return signedMsg
}

func (m SecpMessage) verify(pb *ecdsa.PublicKey, digest, signedMessage []byte) bool {

	if !ecdsa.VerifyASN1(pb, digest, signedMessage) {
		log.Printf("failed to verifyANS1\n\tmessage m: %+v\n\tdigest d: %+v", signedMessage, digest)
		return false
	}

	log.Printf("ANS1 signature verified %v", signedMessage)
	return true
}
