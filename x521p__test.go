package keys_test

import (
	"fmt"
	"testing"

	"github.com/keys-pub/keys"
	"github.com/stretchr/testify/require"
)

func TestNewX521pKeyFromPrivateKey(t *testing.T) {
	// Test new X521pKey and X521pKey from private key are the same
	x521pKey := keys.GenerateX521p()
	x521pKeyOut := keys.NewX521pFromPrivateKey(x521pKey.PrivateKey())

	// require.Equal(t, x521pKey.PrivateKey(), x521pKeyOut.PrivateKey())
	require.Equal(t, x521pKey.PublicKey(), x521pKeyOut.PublicKey())
}

func ExampleGenerateX521pKey(t *testing.T) {
	alice := keys.GenerateX521p()
	fmt.Printf("Alice: %s\n", alice.ID())
}
