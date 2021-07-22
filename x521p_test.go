package keys_test

import (
	"encoding/json"
	"fmt"
	"reflect"
	"testing"

	"github.com/keys-pub/keys"
	"github.com/stretchr/testify/require"
)

func TestNewX521pKeyFromPrivateKey(t *testing.T) {
	// Test new X521pKey and X521pKey from private key are the same
	x521pKey := keys.GenerateX521p()
	x521pKeyOut := keys.NewX521pFromPrivateKey(x521pKey.PrivateKey())

	require.Equal(t, x521pKey.PrivateKey(), x521pKeyOut.PrivateKey())

	// require.Equal(t, x521pKey.PublicKey(), x521pKeyOut.PublicKey())
}

func TestGenerateX521pKey(t *testing.T) {
	alice := keys.GenerateX521p()
	bob := keys.GenerateX521p()
	t.Logf("\nalice -> %s\nbob -> %s", fmtI(alice), fmtI(bob))
	require.Equal(t, reflect.TypeOf(alice), reflect.TypeOf(bob))
}
func fmtI(v interface{}) string {
	b, err := json.MarshalIndent(v, "	", "")
	if err != nil {
		return err.Error()
	}
	return fmt.Sprintln(string(b))
}
