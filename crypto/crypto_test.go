package auth

import (
	"testing"

	"github.com/dtroode/gophkeeper-auth/model"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewCryptoStrategy(t *testing.T) {
	strategy := NewCryptoStrategy()

	assert.NotNil(t, strategy)

	cryptoStrategy, ok := strategy.(*CryptoStrategy)
	require.True(t, ok)

	assert.NotNil(t, cryptoStrategy.KeyDerivator)
	assert.NotNil(t, cryptoStrategy.KeySplitter)
}

func TestCryptoStrategy_Integration(t *testing.T) {
	strategy := NewCryptoStrategy()

	password := []byte("test-password")
	kdf := model.KDFParams{Time: 1, MemKiB: 64 * 1024, Par: 1}
	salt := []byte("test-salt-16-byt")

	rootKey := strategy.DeriveRootKey(password, kdf, salt)
	require.NotNil(t, rootKey)
	require.Len(t, rootKey, 32)

	keys, err := strategy.SplitKeys(rootKey, "server", "client")
	require.NoError(t, err)
	require.Len(t, keys, 2)

	serverKeyReader := keys[0]
	clientKeyReader := keys[1]
	require.NotNil(t, serverKeyReader)
	require.NotNil(t, clientKeyReader)

	rootKey2 := strategy.DeriveRootKey(password, kdf, salt)
	require.Equal(t, rootKey, rootKey2)
}

func TestCryptoStrategy_DifferentPasswords(t *testing.T) {
	strategy := NewCryptoStrategy()

	kdf := model.KDFParams{Time: 1, MemKiB: 64 * 1024, Par: 1}
	salt := []byte("test-salt-16-byt")

	rootKey1 := strategy.DeriveRootKey([]byte("password1"), kdf, salt)
	rootKey2 := strategy.DeriveRootKey([]byte("password2"), kdf, salt)

	require.NotEqual(t, rootKey1, rootKey2)
}

func TestCryptoStrategy_DifferentSalts(t *testing.T) {
	strategy := NewCryptoStrategy()

	password := []byte("test-password")
	kdf := model.KDFParams{Time: 1, MemKiB: 64 * 1024, Par: 1}

	rootKey1 := strategy.DeriveRootKey(password, kdf, []byte("salt1-16-bytes!!!"))
	rootKey2 := strategy.DeriveRootKey(password, kdf, []byte("salt2-16-bytes!!!"))

	require.NotEqual(t, rootKey1, rootKey2)
}
