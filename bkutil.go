package keys

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"log"
	"math/big"
)

func RandomTestSeed(b byte) *[32]byte {
	result := &[32]byte{}
	p := 0
	for p < 32 {
		result[p] = RandomPrime(256)[p%2*p/2] ^ b
		p++
	}
	return result
}

func FixedTestSeed(b byte) *[32]byte {
	result := &[32]byte{}
	v, u, p := b&^(b<<2), b&^(b>>2), 0
	for p < 32 {
		result[p] = v ^ (u * byte(p))
		p++
	}
	return result
}

func RandomPrimeInt(bits int) *big.Int {
	bigInt, err := rand.Prime(rand.Reader, bits)
	if err != nil {
		log.Fatal(err)
	}
	return bigInt
}

func RandomPrime(bits int) []byte {

	return RandomPrimeInt(bits).Bytes()
}

func FixedXOR(src []byte) chan []byte {
	src = <-EncodeHex(src)
	t := (len(src) / 2) - (len(src) % 2)
	dst := make([]byte, t)
	for i := 0; i < t; i++ {
		dst[i] = src[i] ^ src[i+t]
	}
	return DecodeHex(dst)
}

func DecodeBase64(arr []byte) chan []byte {
	ch := make(chan []byte, 1)
	go decodeBase64(arr, ch)
	return ch
}

func decodeBase64(arr []byte, c chan []byte) {
	buffer := make([]byte, base64.StdEncoding.DecodedLen(len(arr)))
	if _, err := base64.StdEncoding.Decode(buffer, arr); err != nil {
		log.Printf("WARN: failed to decode b64\n\tsrc: %v\n\terr: %v", arr, err)
	}
	c <- buffer
}

func EncodeBase64(arr []byte) chan []byte {
	ch := make(chan []byte, 1)
	go encodeBase(arr, ch)
	return ch
}

func encodeBase(arr []byte, c chan []byte) {
	buffer := make([]byte, base64.StdEncoding.EncodedLen(len(arr)))
	base64.StdEncoding.Encode(buffer, arr)
	c <- buffer
}

func DecodeHex(src []byte) chan []byte {
	ch := make(chan []byte, 1)
	go decodeHex(ch, src)
	return ch
}

func decodeHex(c chan []byte, b []byte) {
	buffer := make([]byte, hex.DecodedLen(len(b)))
	if _, err := hex.Decode(buffer, b); err != nil {
		log.Printf("WARN: failed to decode hex\n\tsrc: %v\n\terr: %v", b, err)
	}
	c <- buffer
}

func EncodeHex(src []byte) chan []byte {
	ch := make(chan []byte, 1)
	go encodeHex(ch, src)
	return ch
}

func encodeHex(c chan []byte, b []byte) {
	buffer := make([]byte, hex.EncodedLen(len(b)))
	hex.Encode(buffer, b)
	c <- buffer
}

func Sum(nums ...byte) int {
	var res uint8 = 0
	for _, n := range nums {
		res += uint8(n)
	}
	return int(res)
}

func AreEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for p := 0; p < len(a); p++ {
		if a[p] != b[p] {
			return false
		}
	}
	return true
}
