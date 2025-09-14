package scram

import (
	"context"
	"errors"
	"io"
	"testing"

	"github.com/dtroode/gophkeeper-auth/model"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

type MockCryptoStrategy struct {
	mock.Mock
}

func (m *MockCryptoStrategy) DeriveRootKey(password []byte, kdf model.KDFParams, saltRoot []byte) []byte {
	args := m.Called(password, kdf, saltRoot)
	return args.Get(0).([]byte)
}

func (m *MockCryptoStrategy) SplitKeys(rootKey []byte, labels ...string) ([]io.Reader, error) {
	args := m.Called(rootKey, labels)
	return args.Get(0).([]io.Reader), args.Error(1)
}

type MockServerConnector struct {
	mock.Mock
}

func (m *MockServerConnector) GetRegParams(ctx context.Context, login string) (model.RegParams, error) {
	args := m.Called(ctx, login)
	return args.Get(0).(model.RegParams), args.Error(1)
}

func (m *MockServerConnector) CompleteReg(ctx context.Context, params model.RegComplete) error {
	args := m.Called(ctx, params)
	return args.Error(0)
}

func (m *MockServerConnector) GetLoginParams(ctx context.Context, params model.LoginStart) (model.LoginParams, error) {
	args := m.Called(ctx, params)
	return args.Get(0).(model.LoginParams), args.Error(1)
}

func (m *MockServerConnector) CompleteLogin(ctx context.Context, params model.LoginComplete) (model.SessionResult, error) {
	args := m.Called(ctx, params)
	return args.Get(0).(model.SessionResult), args.Error(1)
}

type MockReader struct {
	data []byte
	pos  int
}

func NewMockReader(data []byte) *MockReader {
	return &MockReader{data: data, pos: 0}
}

func (m *MockReader) Read(p []byte) (n int, err error) {
	if m.pos >= len(m.data) {
		return 0, io.EOF
	}
	n = copy(p, m.data[m.pos:])
	m.pos += n
	if n < len(p) {
		return n, io.EOF
	}
	return n, nil
}

func TestNewBaseClientProtocol(t *testing.T) {
	protocol := NewBaseClientProtocol(nil, nil)
	assert.NotNil(t, protocol)
}

func TestBaseClientProtocol_Struct(t *testing.T) {
	protocol := &BaseClientProtocol{
		SCRAM:           SCRAM{},
		cryptoStrategy:  nil,
		serverConnector: nil,
	}

	assert.NotNil(t, protocol)
	require.NotNil(t, protocol.SCRAM)
}

func TestBaseClientProtocol_RegisterUser_Success(t *testing.T) {
	ctx := context.Background()
	mockCrypto := &MockCryptoStrategy{}
	mockConnector := &MockServerConnector{}

	protocol := NewBaseClientProtocol(mockCrypto, mockConnector)

	params := model.RegisterRequest{
		Login:    "test@user.com",
		Password: "password123",
		UserData: model.UserData{FirstName: "Test", LastName: "User"},
	}

	serverParams := model.RegParams{
		SessionID: "session-123",
		KDFParams: model.KDFParams{Time: 1, MemKiB: 1024, Par: 1},
		SaltRoot:  []byte("salt-root"),
	}

	rootKey := []byte("root-key-32-bytes-long-exactly")
	authReader := NewMockReader(make([]byte, 32))
	masterReader := NewMockReader(make([]byte, 32))

	mockConnector.On("GetRegParams", ctx, params.Login).Return(serverParams, nil)
	mockCrypto.On("DeriveRootKey", []byte(params.Password), serverParams.KDFParams, serverParams.SaltRoot).Return(rootKey)
	mockCrypto.On("SplitKeys", rootKey, []string{model.AuthLabel, model.MKLabel}).Return([]io.Reader{authReader, masterReader}, nil)
	mockConnector.On("CompleteReg", ctx, mock.MatchedBy(func(complete model.RegComplete) bool {
		return complete.Login == params.Login && complete.SessionID == serverParams.SessionID
	})).Return(nil)

	result, err := protocol.RegisterUser(ctx, params)

	require.NoError(t, err)
	assert.Equal(t, make([]byte, 32), result.AuthKey)
	assert.Equal(t, make([]byte, 32), result.MasterKey)
	mockCrypto.AssertExpectations(t)
	mockConnector.AssertExpectations(t)
}

func TestBaseClientProtocol_RegisterUser_GetRegParamsError(t *testing.T) {
	ctx := context.Background()
	mockCrypto := &MockCryptoStrategy{}
	mockConnector := &MockServerConnector{}

	protocol := NewBaseClientProtocol(mockCrypto, mockConnector)

	params := model.RegisterRequest{
		Login:    "test@user.com",
		Password: "password123",
	}

	mockConnector.On("GetRegParams", ctx, params.Login).Return(model.RegParams{}, errors.New("server error"))

	result, err := protocol.RegisterUser(ctx, params)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to start registration")
	assert.Equal(t, model.RegResult{}, result)
	mockConnector.AssertExpectations(t)
}

func TestBaseClientProtocol_LoginUser_Success(t *testing.T) {
	ctx := context.Background()
	mockCrypto := &MockCryptoStrategy{}
	mockConnector := &MockServerConnector{}

	protocol := NewBaseClientProtocol(mockCrypto, mockConnector)

	params := model.LoginRequest{
		Login:    "test@user.com",
		Password: "password123",
	}

	serverParams := model.LoginParams{
		SessionID:   "session-123",
		KDFParams:   model.KDFParams{Time: 1, MemKiB: 1024, Par: 1},
		SaltRoot:    []byte("salt-root"),
		ServerNonce: []byte("server-nonce"),
	}

	rootKey := []byte("root-key-32-bytes-long-exactly")
	authReader := NewMockReader(make([]byte, 32))
	masterReader := NewMockReader(make([]byte, 32))

	loginResponse := model.SessionResult{
		AccessToken:  "access-token",
		RefreshToken: "refresh-token",
	}

	mockConnector.On("GetLoginParams", ctx, mock.MatchedBy(func(start model.LoginStart) bool {
		return start.Login == params.Login
	})).Return(serverParams, nil)
	mockCrypto.On("DeriveRootKey", []byte(params.Password), serverParams.KDFParams, serverParams.SaltRoot).Return(rootKey)
	mockCrypto.On("SplitKeys", rootKey, []string{model.AuthLabel, model.MKLabel}).Return([]io.Reader{authReader, masterReader}, nil)
	mockConnector.On("CompleteLogin", ctx, mock.MatchedBy(func(complete model.LoginComplete) bool {
		return complete.Login == params.Login && complete.SessionID == serverParams.SessionID
	})).Return(loginResponse, nil)

	result, err := protocol.LoginUser(ctx, params)

	require.NoError(t, err)
	assert.Equal(t, make([]byte, 32), result.MasterKey)
	assert.Equal(t, "access-token", result.AccessToken)
	assert.Equal(t, "refresh-token", result.RefreshToken)
	mockCrypto.AssertExpectations(t)
	mockConnector.AssertExpectations(t)
}

func TestBaseClientProtocol_splitKeys_Success(t *testing.T) {
	mockCrypto := &MockCryptoStrategy{}
	mockConnector := &MockServerConnector{}

	protocol := NewBaseClientProtocol(mockCrypto, mockConnector)

	rootKey := []byte("root-key")
	authReader := NewMockReader(make([]byte, 32))
	masterReader := NewMockReader(make([]byte, 32))

	mockCrypto.On("SplitKeys", rootKey, []string{model.AuthLabel, model.MKLabel}).Return([]io.Reader{authReader, masterReader}, nil)

	authKey, masterKey, err := protocol.splitKeys(rootKey)

	require.NoError(t, err)
	assert.Equal(t, make([]byte, 32), authKey)
	assert.Equal(t, make([]byte, 32), masterKey)
	mockCrypto.AssertExpectations(t)
}
