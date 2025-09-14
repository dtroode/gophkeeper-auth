package derivator

import (
	"testing"

	"github.com/dtroode/gophkeeper-auth/model"
	"github.com/stretchr/testify/require"
)

func TestArgon2Derivator_DeriveRootKey(t *testing.T) {
	d := NewArgon2Derivator()
	p := model.KDFParams{Time: 1, MemKiB: 64 * 1024, Par: 1}
	password := []byte("password")
	salt := []byte("fixed-salt-16-bytes")

	key1 := d.DeriveRootKey(password, p, salt)
	key2 := d.DeriveRootKey(password, p, salt)
	require.Equal(t, 32, len(key1))
	require.Equal(t, key1, key2)

	key3 := d.DeriveRootKey([]byte("password2"), p, salt)
	require.NotEqual(t, key1, key3)
}
