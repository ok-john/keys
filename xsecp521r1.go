package keys

import "crypto/sha512"

// What format should i use here?
const (
	Xsecp521r1pKey    KeyType     = "secp521r1"
	Xsecp521r1pKeyHRP string      = "kbx"
	testMessage       SecpMessage = "super-baked"
)

type (
	SecpMessage string
)

func NewMSG(msg string) SecpMessage {
	return SecpMessage(msg)
}

func StaticMSG() SecpMessage {
	return testMessage
}

func (m SecpMessage) bytes() []byte {
	return []byte(m)
}

func (m SecpMessage) digest() [sha512.Size]byte {
	return sha512.Sum512(m.bytes())
}
