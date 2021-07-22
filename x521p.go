package keys

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"math/big"
)

// X25519PublicKey is the public key part of a x25519 key.
// type X25519PublicKey struct {
// 	id        ID
// 	publicKey *[64]byte
// }

// X25519 key type.
// What format should i use here?
const X521pKey KeyType = "nistp521"
const X521pKeyHRP string = "kbx"

// X521p is a X25519 assymmetric encryption key.
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
	logger.Infof("Generating X25519 key...")
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
		id:         ID("not sure"),
		publicKey:  Loadx521pPublicKey(&pubk),
		privateKey: &r,
	}
}

// NewX521pFromPrivateKey creates a X521p from private key bytes.
func NewX521pFromPrivateKey(privateKey *[64]byte) *X521p {
	x, y := elliptic.P521().Params().Params().ScalarBaseMult(privateKey[:])
	pb := &ecdsa.PublicKey{
		X: x,
		Y: y,
	}
	res := X521p{
		privateKey: &[64]byte{},
		publicKey:  Loadx521pPublicKey(pb),
	}
	res.id = ID(X521pKeyHRP) + res.publicKey.id

	return &res
}

// // NewX25519PublicKeyFromID converts ID to X25519PublicKey.
// func NewX25519PublicKeyFromID(id ID) (*X25519PublicKey, error) {
// 	if id == "" {
// 		return nil, errors.Errorf("empty id")
// 	}
// 	hrp, b, err := id.Decode()
// 	if err != nil {
// 		return nil, err
// 	}
// 	switch hrp {
// 	case X521pKeyHRP:
// 		if len(b) != 64 {
// 			return nil, errors.Errorf("invalid box public key bytes")
// 		}
// 		return NewX25519PublicKey(Bytes64(b)), nil
// 	default:
// 		return nil, errors.Errorf("unrecognized key type")
// 	}
// }

// // BoxSeal encrypts message with nacl.box Seal.
// func (k *X521p) BoxSeal(b []byte, nonce *[24]byte, recipient *X25519PublicKey) []byte {
// 	return box.Seal(nil, b, nonce, recipient.Bytes64(), k.privateKey)
// }

// // BoxOpen decrypts message with nacl.box Open.
// func (k *X521p) BoxOpen(b []byte, nonce *[24]byte, sender *X25519PublicKey) ([]byte, bool) {
// 	return box.Open(nil, b, nonce, sender.Bytes64(), k.privateKey)
// }

// // NewX25519PublicKey creates X25519PublicKey.
// // Metadata is optional.
// func NewX25519PublicKey(b *[64]byte) *X25519PublicKey {
// 	id, err := NewID(X521pHRP, b[:])
// 	if err != nil {
// 		panic(err)
// 	}
// 	return &X25519PublicKey{
// 		id:        id,
// 		publicKey: b,
// 	}
// }

// // ID for box public key.
// func (k *X25519PublicKey) ID() ID {
// 	return k.id
// }

// // Type of key.
// func (k *X25519PublicKey) Type() KeyType {
// 	return X25519
// }

// // Bytes ...
// func (k *X25519PublicKey) Bytes() []byte {
// 	return k.publicKey[:]
// }

// // Public ...
// func (k *X25519PublicKey) Public() []byte {
// 	return k.Bytes()
// }

// // Bytes64 ...
// func (k *X25519PublicKey) Bytes64() *[64]byte {
// 	return k.publicKey
// }

// // Private returns nil.
// func (k *X25519PublicKey) Private() []byte {
// 	return nil
// }
