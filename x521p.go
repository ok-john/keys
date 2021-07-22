package keys

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"math/big"
)

// What format should i use here?
const X521pKey KeyType = "nistp521"
const X521pKeyHRP string = "kbx"

type X521p struct {
	id         ID
	publicKey  *x521pPublicKey
	privateKey *[64]byte
}

type x521pPublicKey struct {
	id        ID
	pb        *ecdsa.PublicKey
	publicKey *[64]byte
}

type x521pPrivateKey struct {
	id         ID
	pb         *ecdsa.PublicKey
	privateKey *[64]byte
}

func Loadx521pPublicKey(ecpb *ecdsa.PublicKey) *x521pPublicKey {
	return &x521pPublicKey{
		id:        ID(X521pKeyHRP),
		pb:        ecpb,
		publicKey: Flatten(ecpb),
	}
}

// ID is key identifer.
func (k *X521p) ID() ID {
	return k.id
}
func Flatten(ec *ecdsa.PublicKey) *[64]byte {
	res := [64]byte{}
	for i, v := range append(ec.X.Bytes(), ec.Y.Bytes()...) {
		if i >= 63 {
			break
		}
		res[i] = v
	}
	return &res
}

// Type of key.
func (k *X521p) Type() KeyType {
	return X521pKey
}

// Public key bytes.
func (k *X521p) Public() []byte {
	return Flatten(k.publicKey.pb)[:]
}

// Private key bytes.
func (k *X521p) Private() []byte {
	return k.privateKey[:]
}

// Bytes64 private key bytes.
func (k *X521p) Bytes64() *[64]byte {
	return k.privateKey
}

// PrivateKey returns private part of this X521p.
func (k *X521p) PrivateKey() *[64]byte {
	return k.privateKey
}

// PublicKey returns public part of this X521p.
func (k *X521p) PublicKey() *[64]byte {
	return Flatten(k.publicKey.pb)
}

// GenerateX521p creates a new X521p.
func GenerateX521p() *X521p {
	logger.Infof("Generating X521p key...")
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

	b := big.NewInt(512).SetBytes(pk).Bytes()
	var r [64]byte = [64]byte{}
	for i, bt := range b[:64] {
		r[i] = bt
	}
	return &X521p{
		id:         ID(X521pKeyHRP),
		publicKey:  Loadx521pPublicKey(&pubk),
		privateKey: &r,
	}
}

// NewX521pFromPrivateKey creates a X521p from private key bytes.
func NewX521pFromPrivateKey(privateKey *[64]byte) *X521p {
	x, y := elliptic.P521().Params().Params().ScalarBaseMult(privateKey[:])
	return &X521p{
		id:         ID(X521pKeyHRP),
		privateKey: privateKey,
		publicKey: Loadx521pPublicKey(&ecdsa.PublicKey{
			X: x,
			Y: y,
		}),
	}
}
