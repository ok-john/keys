package keys

import (
	"reflect"
	"testing"
)

type (
	secp512r1Test struct {
		name string
		m    SecpMessage
		want []byte
	}
)

func TestSecpMessage_digest(t *testing.T) {
	tests := []secp512r1Test{
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
