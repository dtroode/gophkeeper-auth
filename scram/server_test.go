package scram

import (
	"context"
	"testing"
	"time"

	"github.com/dtroode/gophkeeper-auth/model"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type MockLogger struct {
	InfoCalls  [][]interface{}
	ErrorCalls [][]interface{}
	DebugCalls [][]interface{}
}

func (m *MockLogger) Info(msg string, args ...any) {
	m.InfoCalls = append(m.InfoCalls, append([]interface{}{msg}, args...))
}

func (m *MockLogger) Error(msg string, args ...any) {
	m.ErrorCalls = append(m.ErrorCalls, append([]interface{}{msg}, args...))
}

func (m *MockLogger) Debug(msg string, args ...any) {
	m.DebugCalls = append(m.DebugCalls, append([]interface{}{msg}, args...))
}

func TestNewBaseServerProtocol(t *testing.T) {
	kdf := model.KDFParams{Time: 1, MemKiB: 1024, Par: 1}
	logger := &MockLogger{}

	protocol := NewBaseServerProtocol(kdf, logger)

	assert.NotNil(t, protocol)
	assert.NotNil(t, protocol.SCRAM)
	assert.Equal(t, logger, protocol.logger)
}

func TestBaseServerProtocol_PrepareRegistration(t *testing.T) {
	kdf := model.KDFParams{Time: 1, MemKiB: 1024, Par: 1}
	logger := &MockLogger{}
	ctx := context.Background()

	protocol := NewBaseServerProtocol(kdf, logger)
	params, err := protocol.PrepareRegistration(ctx)

	require.NoError(t, err)
	assert.NotEmpty(t, params.SessionID)
	assert.Equal(t, kdf, params.KDFParams)
	assert.NotEmpty(t, params.SaltRoot)
}

func TestBaseServerProtocol_VerifyRegistration(t *testing.T) {
	kdf := model.KDFParams{Time: 1, MemKiB: 1024, Par: 1}
	logger := &MockLogger{}
	ctx := context.Background()

	protocol := NewBaseServerProtocol(kdf, logger)

	pending := model.PendingReg{
		SessionID: uuid.NewString(),
		Login:     "test@example.com",
		SaltRoot:  []byte("salt-root-16-byt"),
		ExpiresAt: time.Now().Add(-time.Hour),
		Consumed:  false,
	}

	complete := model.RegComplete{
		SessionID: pending.SessionID,
		ServerKey: []byte("server-key"),
	}

	err := protocol.VerifyRegistration(ctx, pending, complete)
	require.Error(t, err)
}

func TestBaseServerProtocol_PrepareLogin(t *testing.T) {
	kdf := model.KDFParams{Time: 1, MemKiB: 1024, Par: 1}
	logger := &MockLogger{}
	ctx := context.Background()

	protocol := NewBaseServerProtocol(kdf, logger)
	params, err := protocol.PrepareLogin(ctx)

	require.NoError(t, err)
	assert.NotEmpty(t, params.SessionID)
	assert.NotEmpty(t, params.ServerNonce)
}

func TestBaseServerProtocol_VerifyLogin(t *testing.T) {
	kdf := model.KDFParams{Time: 1, MemKiB: 1024, Par: 1}
	logger := &MockLogger{}
	ctx := context.Background()

	protocol := NewBaseServerProtocol(kdf, logger)

	serverKey := []byte("server-key-32-bytes-for-testing!")

	pending := model.PendingLogin{
		SessionID: "session-1",
		Login:     "test@example.com",
		ExpiresAt: time.Now().Add(-time.Hour),
		Consumed:  false,
	}

	complete := model.LoginComplete{
		SessionID:   "session-2",
		ClientProof: []byte("client-proof"),
	}

	err := protocol.VerifyLogin(ctx, serverKey, pending, complete)
	require.Error(t, err)
}

func TestBaseServerProtocol_MakeServerSignature(t *testing.T) {
	kdf := model.KDFParams{Time: 1, MemKiB: 1024, Par: 1}
	logger := &MockLogger{}

	protocol := NewBaseServerProtocol(kdf, logger)

	login := "test@example.com"
	serverKey := []byte("server-key")
	clientNonce := []byte("client-nonce")
	serverNonce := []byte("server-nonce")

	signature := protocol.MakeServerSignature(login, serverKey, clientNonce, serverNonce)

	assert.NotNil(t, signature)
	assert.Len(t, signature, 32)
}

func TestBaseServerProtocol_PrepareRegistration_Success(t *testing.T) {
	mockLogger := &MockLogger{}
	protocol := NewBaseServerProtocol(model.KDFParams{Time: 1, MemKiB: 1024, Par: 1}, mockLogger)

	result, err := protocol.PrepareRegistration(context.Background())

	require.NoError(t, err)
	assert.NotEmpty(t, result.SessionID)
	assert.Equal(t, uint32(1), result.KDFParams.Time)
	assert.Equal(t, uint32(1024), result.KDFParams.MemKiB)
	assert.Equal(t, uint8(1), result.KDFParams.Par)
	assert.NotEmpty(t, result.SaltRoot)
}

func TestBaseServerProtocol_PrepareLogin_Success(t *testing.T) {
	mockLogger := &MockLogger{}
	protocol := NewBaseServerProtocol(model.KDFParams{Time: 1, MemKiB: 1024, Par: 1}, mockLogger)

	result, err := protocol.PrepareLogin(context.Background())

	require.NoError(t, err)
	assert.NotEmpty(t, result.SessionID)
	assert.NotEmpty(t, result.ServerNonce)
}

func TestBaseServerProtocol_VerifyRegistration_SaltRootMismatch(t *testing.T) {
	mockLogger := &MockLogger{}
	protocol := NewBaseServerProtocol(model.KDFParams{Time: 1, MemKiB: 1024, Par: 1}, mockLogger)

	pendingReg := model.PendingReg{
		SessionID: "session-123",
		Login:     "test@user.com",
		SaltRoot:  []byte("salt-root"),
		KDF:       []byte(`{"time":1,"memKiB":1024,"par":1}`),
		ExpiresAt: time.Now().Add(time.Hour),
		Consumed:  false,
	}

	params := model.RegComplete{
		Login:     "test@user.com",
		SaltRoot:  []byte("different-salt"), // Different salt
		KDF:       model.KDFParams{Time: 1, MemKiB: 1024, Par: 1},
		StoredKey: make([]byte, 32),
		ServerKey: make([]byte, 32),
	}

	err := protocol.VerifyRegistration(context.Background(), pendingReg, params)
	require.Error(t, err)
}

func TestBaseServerProtocol_VerifyRegistration_KDFMismatch(t *testing.T) {
	mockLogger := &MockLogger{}
	protocol := NewBaseServerProtocol(model.KDFParams{Time: 1, MemKiB: 1024, Par: 1}, mockLogger)

	pendingReg := model.PendingReg{
		SessionID: "session-123",
		Login:     "test@user.com",
		SaltRoot:  []byte("salt-root"),
		KDF:       []byte(`{"time":1,"memKiB":1024,"par":1}`),
		ExpiresAt: time.Now().Add(time.Hour),
		Consumed:  false,
	}

	params := model.RegComplete{
		Login:     "test@user.com",
		SaltRoot:  []byte("salt-root"),
		KDF:       model.KDFParams{Time: 2, MemKiB: 2048, Par: 2}, // Different KDF
		StoredKey: make([]byte, 32),
		ServerKey: make([]byte, 32),
	}

	err := protocol.VerifyRegistration(context.Background(), pendingReg, params)
	require.Error(t, err)
}

func TestBaseServerProtocol_VerifyRegistration_InvalidStoredKeyLength(t *testing.T) {
	mockLogger := &MockLogger{}
	protocol := NewBaseServerProtocol(model.KDFParams{Time: 1, MemKiB: 1024, Par: 1}, mockLogger)

	pendingReg := model.PendingReg{
		SessionID: "session-123",
		Login:     "test@user.com",
		SaltRoot:  []byte("salt-root"),
		KDF:       []byte(`{"time":1,"memKiB":1024,"par":1}`),
		ExpiresAt: time.Now().Add(time.Hour),
		Consumed:  false,
	}

	params := model.RegComplete{
		Login:     "test@user.com",
		SaltRoot:  []byte("salt-root"),
		KDF:       model.KDFParams{Time: 1, MemKiB: 1024, Par: 1},
		StoredKey: make([]byte, 16), // Invalid length
		ServerKey: make([]byte, 32),
	}

	err := protocol.VerifyRegistration(context.Background(), pendingReg, params)
	require.Error(t, err)
}

func TestBaseServerProtocol_VerifyRegistration_InvalidServerKeyLength(t *testing.T) {
	mockLogger := &MockLogger{}
	protocol := NewBaseServerProtocol(model.KDFParams{Time: 1, MemKiB: 1024, Par: 1}, mockLogger)

	pendingReg := model.PendingReg{
		SessionID: "session-123",
		Login:     "test@user.com",
		SaltRoot:  []byte("salt-root"),
		KDF:       []byte(`{"time":1,"memKiB":1024,"par":1}`),
		ExpiresAt: time.Now().Add(time.Hour),
		Consumed:  false,
	}

	params := model.RegComplete{
		Login:     "test@user.com",
		SaltRoot:  []byte("salt-root"),
		KDF:       model.KDFParams{Time: 1, MemKiB: 1024, Par: 1},
		StoredKey: make([]byte, 32),
		ServerKey: make([]byte, 16), // Invalid length
	}

	err := protocol.VerifyRegistration(context.Background(), pendingReg, params)
	require.Error(t, err)
}
