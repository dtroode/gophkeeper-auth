package scram

import (
	"testing"

	"github.com/dtroode/gophkeeper-auth/model"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewSCRAM(t *testing.T) {
	kdf := model.KDFParams{Time: 1, MemKiB: 1024, Par: 1}
	scram := NewSCRAM(kdf)

	assert.NotNil(t, scram)
	assert.Equal(t, kdf, scram.KDFParams)
}

func TestSCRAM_GetKDFParams(t *testing.T) {
	kdf := model.KDFParams{Time: 2, MemKiB: 2048, Par: 2}
	scram := NewSCRAM(kdf)

	result, err := scram.GetKDFParams()
	require.NoError(t, err)
	assert.Equal(t, kdf, result)
}

func TestSCRAM_BuildVerifiers(t *testing.T) {
	kdf := model.KDFParams{Time: 1, MemKiB: 1024, Par: 1}
	scram := NewSCRAM(kdf)

	authKey := []byte("test-auth-key-32-bytes-for-test!")
	storedKey, serverKey := scram.BuildVerifiers(authKey)

	assert.NotNil(t, storedKey)
	assert.NotNil(t, serverKey)
	assert.Len(t, storedKey, 32)
	assert.Len(t, serverKey, 32)
	assert.NotEqual(t, storedKey, serverKey)
}

func TestSCRAM_BuildVerifiers_Deterministic(t *testing.T) {
	kdf := model.KDFParams{Time: 1, MemKiB: 1024, Par: 1}
	scram := NewSCRAM(kdf)

	authKey := []byte("test-auth-key-32-bytes-for-test!")

	storedKey1, serverKey1 := scram.BuildVerifiers(authKey)
	storedKey2, serverKey2 := scram.BuildVerifiers(authKey)

	assert.Equal(t, storedKey1, storedKey2)
	assert.Equal(t, serverKey1, serverKey2)
}

func TestSCRAM_BuildVerifiers_DifferentKeys(t *testing.T) {
	kdf := model.KDFParams{Time: 1, MemKiB: 1024, Par: 1}
	scram := NewSCRAM(kdf)

	authKey1 := []byte("test-auth-key1-32-bytes-for-test")
	authKey2 := []byte("test-auth-key2-32-bytes-for-test")

	storedKey1, serverKey1 := scram.BuildVerifiers(authKey1)
	storedKey2, serverKey2 := scram.BuildVerifiers(authKey2)

	assert.NotEqual(t, storedKey1, storedKey2)
	assert.NotEqual(t, serverKey1, serverKey2)
}

func TestSCRAM_GenerateNonce(t *testing.T) {
	kdf := model.KDFParams{Time: 1, MemKiB: 1024, Par: 1}
	scram := NewSCRAM(kdf)

	nonce1, err1 := scram.GenerateNonce()
	require.NoError(t, err1)
	assert.Len(t, nonce1, 16)

	nonce2, err2 := scram.GenerateNonce()
	require.NoError(t, err2)
	assert.Len(t, nonce2, 16)

	assert.NotEqual(t, nonce1, nonce2)
}

func TestSCRAM_MakeClientProof(t *testing.T) {
	kdf := model.KDFParams{Time: 1, MemKiB: 1024, Par: 1}
	scram := NewSCRAM(kdf)

	authKey := []byte("auth-key-32-bytes-for-testing!!!")
	storedKey := []byte("stored-key-32-bytes-for-testing!")
	authMessage := []byte("auth-message")

	clientProof := scram.MakeClientProof(authKey, storedKey, authMessage)
	assert.NotNil(t, clientProof)
	assert.Len(t, clientProof, 32)
}

func TestSCRAM_MakeServerSignature(t *testing.T) {
	kdf := model.KDFParams{Time: 1, MemKiB: 1024, Par: 1}
	scram := NewSCRAM(kdf)

	login := "test@example.com"
	serverKey := []byte("server-key-32-bytes-for-testing!")
	clientNonce := []byte("client-nonce")
	serverNonce := []byte("server-nonce")

	signature := scram.MakeServerSignature(login, serverKey, clientNonce, serverNonce)
	assert.NotNil(t, signature)
	assert.Len(t, signature, 32)
}

func TestSCRAM_GenerateSaltRoot(t *testing.T) {
	kdf := model.KDFParams{Time: 1, MemKiB: 1024, Par: 1}
	scram := NewSCRAM(kdf)

	salt1, err1 := scram.GenerateSaltRoot()
	require.NoError(t, err1)
	assert.Len(t, salt1, 32)

	salt2, err2 := scram.GenerateSaltRoot()
	require.NoError(t, err2)
	assert.Len(t, salt2, 32)

	assert.NotEqual(t, salt1, salt2)
}

func TestSCRAM_GenerateServerNonce(t *testing.T) {
	kdf := model.KDFParams{Time: 1, MemKiB: 1024, Par: 1}
	scram := NewSCRAM(kdf)

	nonce1, err1 := scram.GenerateServerNonce()
	require.NoError(t, err1)
	assert.Len(t, nonce1, 16)

	nonce2, err2 := scram.GenerateServerNonce()
	require.NoError(t, err2)
	assert.Len(t, nonce2, 16)

	assert.NotEqual(t, nonce1, nonce2)
}

func TestSCRAM_Structure(t *testing.T) {
	kdf := model.KDFParams{Time: 3, MemKiB: 4096, Par: 4}

	scram := &SCRAM{
		KDFParams: kdf,
	}

	assert.NotNil(t, scram)
	assert.Equal(t, kdf, scram.KDFParams)
}

func TestSCRAM_DeriveClientKey_Success(t *testing.T) {
	scram := NewSCRAM(model.KDFParams{Time: 1, MemKiB: 1024, Par: 1})

	clientProof := []byte{1, 2, 3, 4, 5}
	clientSignature := []byte{5, 4, 3, 2, 1}

	result, err := scram.DeriveClientKey(clientProof, clientSignature)

	require.NoError(t, err)
	expected := []byte{4, 6, 0, 6, 4} // XOR of clientProof and clientSignature
	assert.Equal(t, expected, result)
}

func TestSCRAM_DeriveClientKey_LengthMismatch(t *testing.T) {
	scram := NewSCRAM(model.KDFParams{Time: 1, MemKiB: 1024, Par: 1})

	clientProof := []byte{1, 2, 3}
	clientSignature := []byte{5, 4, 3, 2, 1} // Different length

	result, err := scram.DeriveClientKey(clientProof, clientSignature)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "client proof and client signature must have the same length")
	assert.Nil(t, result)
}

func TestSCRAM_DeriveClientKey_Empty(t *testing.T) {
	scram := NewSCRAM(model.KDFParams{Time: 1, MemKiB: 1024, Par: 1})

	clientProof := []byte{}
	clientSignature := []byte{}

	result, err := scram.DeriveClientKey(clientProof, clientSignature)

	require.NoError(t, err)
	assert.Equal(t, []byte{}, result)
}

func TestSCRAM_DeriveClientKey_SingleByte(t *testing.T) {
	scram := NewSCRAM(model.KDFParams{Time: 1, MemKiB: 1024, Par: 1})

	clientProof := []byte{0xFF}
	clientSignature := []byte{0x00}

	result, err := scram.DeriveClientKey(clientProof, clientSignature)

	require.NoError(t, err)
	assert.Equal(t, []byte{0xFF}, result)
}
