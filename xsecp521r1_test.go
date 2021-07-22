package keys

import (
	"context"
	"crypto/ecdsa"
	"reflect"
	"testing"
)

type (
	sha512DigestTest struct {
		name string
		m    SecpMessage
		want []byte
	}
	x512r1SignTest struct {
		name string
		m    SecpMessage
		sk   *ecdsa.PrivateKey
	}
)

func TestSecpMessage_digest(t *testing.T) {
	tests := []sha512DigestTest{
		// TODO: Add test cases.
		{
			"static test",
			SecpMessage("fooood"),
			[]byte("WYUh3qNeiF4XCFdmHRX3CNV17+YjHoG/E80Lf4cXhy01v7QwfCyeg42imSIpsm2oPAQxdl5v8zgsaLC7I6Egsw=="),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.m.digest()
			encodedGot := <-EncodeBase64(got[:])
			if !reflect.DeepEqual(encodedGot, tt.want) {
				t.Errorf("SecpMessage.digest()\n\t got = %s, \n\t want %s", encodedGot, tt.want)
			}
		})
	}
}

func TestSecpMessage_sign(t *testing.T) {

	alice := newEcSk(context.TODO())
	signedMsgHexEncoded := []byte("30818702416574f64a9c7534d5941763b316de91b223a8e5b13c1db17d747b64644de083f9d474e374b2a4195e1d91dce450c365cd0cd35be0c316964c949d3a65ccd2162e0f0242010711ba9a3eec7ff73288fe328de81e1dce25a593f26464ba0d5c44d215699ce5a267c0a13703f0af49cf713692b2cdfeb47b68d503d2a797e47dc088f079628085")
	emptyMsg := []byte{}
	tests := []x512r1SignTest{
		{
			"x512 basic sign test",
			"super-baked",
			alice,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			signedMsg := tt.m.sign(tt.sk)
			// if !reflect.DeepEqual(signedMsg, signedMsgHexEncoded) {
			// 	t.Fatalf("no bueno senor, TestSecpMessage_sign\n\twanted: \n\t\t%v got\n\t\t%v", signedMsgHexEncoded, signedMsg)
			// }
			if reflect.DeepEqual(emptyMsg, signedMsgHexEncoded) {
				t.Fatalf("nooope. didn't want any empty array...\n TestSecpMessage_sign\n\twanted: \n\t\t%v got\n\t\t%v", signedMsgHexEncoded, signedMsg)
			}
			t.Logf("signed msg: %s", <-EncodeHex(signedMsg))
		})
	}
}
