package api

import (
	"context"
	"errors"
	"testing"

	"github.com/dtroode/gophkeeper-auth/model"
	"github.com/dtroode/gophkeeper-auth/server/proto"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/emptypb"
)

func TestNewConnector(t *testing.T) {
	connector := NewConnector(nil)

	assert.NotNil(t, connector)
	assert.Nil(t, connector.client)
}

func TestConnector_Structure(t *testing.T) {
	connector := &Connector{
		client: nil,
	}

	assert.NotNil(t, connector)
	assert.Nil(t, connector.client)
}

type MockAuthClient struct {
	mock.Mock
}

func (m *MockAuthClient) GetRegParams(ctx context.Context, req *proto.RegStart, opts ...grpc.CallOption) (*proto.RegParams, error) {
	args := m.Called(ctx, req)
	return args.Get(0).(*proto.RegParams), args.Error(1)
}

func (m *MockAuthClient) CompleteReg(ctx context.Context, req *proto.RegComplete, opts ...grpc.CallOption) (*emptypb.Empty, error) {
	args := m.Called(ctx, req)
	return args.Get(0).(*emptypb.Empty), args.Error(1)
}

func (m *MockAuthClient) GetLoginParams(ctx context.Context, req *proto.LoginStart, opts ...grpc.CallOption) (*proto.LoginParams, error) {
	args := m.Called(ctx, req)
	return args.Get(0).(*proto.LoginParams), args.Error(1)
}

func (m *MockAuthClient) CompleteLogin(ctx context.Context, req *proto.LoginComplete, opts ...grpc.CallOption) (*proto.SessionResult, error) {
	args := m.Called(ctx, req)
	return args.Get(0).(*proto.SessionResult), args.Error(1)
}

func (m *MockAuthClient) RefreshToken(ctx context.Context, req *proto.RefreshTokenRequest, opts ...grpc.CallOption) (*proto.RefreshTokenResponse, error) {
	args := m.Called(ctx, req)
	return args.Get(0).(*proto.RefreshTokenResponse), args.Error(1)
}

func (m *MockAuthClient) RevokeToken(ctx context.Context, req *proto.RevokeTokenRequest, opts ...grpc.CallOption) (*emptypb.Empty, error) {
	args := m.Called(ctx, req)
	return args.Get(0).(*emptypb.Empty), args.Error(1)
}

func TestConnector_GetRegParams_Success(t *testing.T) {
	ctx := context.Background()
	mockClient := &MockAuthClient{}
	connector := NewConnector(mockClient)

	expectedResp := &proto.RegParams{
		SessionId: "session-123",
		KdfParams: &proto.KDFParams{
			MemKib: 1024,
			Time:   1,
			Par:    1,
		},
		SaltRoot: []byte("salt-root"),
	}

	mockClient.On("GetRegParams", ctx, &proto.RegStart{Login: "test@user.com"}).Return(expectedResp, nil)

	result, err := connector.GetRegParams(ctx, "test@user.com")

	require.NoError(t, err)
	assert.Equal(t, "session-123", result.SessionID)
	assert.Equal(t, uint32(1024), result.KDFParams.MemKiB)
	assert.Equal(t, uint32(1), result.KDFParams.Time)
	assert.Equal(t, uint8(1), result.KDFParams.Par)
	assert.Equal(t, []byte("salt-root"), result.SaltRoot)
	mockClient.AssertExpectations(t)
}

func TestConnector_GetRegParams_Error(t *testing.T) {
	ctx := context.Background()
	mockClient := &MockAuthClient{}
	connector := NewConnector(mockClient)

	mockClient.On("GetRegParams", ctx, &proto.RegStart{Login: "test@user.com"}).Return((*proto.RegParams)(nil), errors.New("grpc error"))

	result, err := connector.GetRegParams(ctx, "test@user.com")

	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to obtain server registration params")
	assert.Equal(t, model.RegParams{}, result)
	mockClient.AssertExpectations(t)
}

func TestConnector_CompleteReg_Success(t *testing.T) {
	ctx := context.Background()
	mockClient := &MockAuthClient{}
	connector := NewConnector(mockClient)

	params := model.RegComplete{
		SessionID: "session-123",
		Login:     "test@user.com",
		SaltRoot:  []byte("salt-root"),
		KDF:       model.KDFParams{Time: 1, MemKiB: 1024, Par: 1},
		StoredKey: []byte("stored-key"),
		ServerKey: []byte("server-key"),
	}

	mockClient.On("CompleteReg", ctx, mock.MatchedBy(func(req *proto.RegComplete) bool {
		return req.SessionId == params.SessionID && req.Login == params.Login
	})).Return(&emptypb.Empty{}, nil)

	err := connector.CompleteReg(ctx, params)

	require.NoError(t, err)
	mockClient.AssertExpectations(t)
}

func TestConnector_CompleteReg_Error(t *testing.T) {
	ctx := context.Background()
	mockClient := &MockAuthClient{}
	connector := NewConnector(mockClient)

	params := model.RegComplete{
		SessionID: "session-123",
		Login:     "test@user.com",
	}

	mockClient.On("CompleteReg", ctx, mock.AnythingOfType("*proto.RegComplete")).Return((*emptypb.Empty)(nil), errors.New("grpc error"))

	err := connector.CompleteReg(ctx, params)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to register user")
	mockClient.AssertExpectations(t)
}

func TestConnector_GetLoginParams_Success(t *testing.T) {
	ctx := context.Background()
	mockClient := &MockAuthClient{}
	connector := NewConnector(mockClient)

	expectedResp := &proto.LoginParams{
		SessionId:   "session-123",
		KdfParams:   &proto.KDFParams{MemKib: 1024, Time: 1, Par: 1},
		SaltRoot:    []byte("salt-root"),
		ServerNonce: []byte("server-nonce"),
	}

	mockClient.On("GetLoginParams", ctx, mock.MatchedBy(func(req *proto.LoginStart) bool {
		return req.Login == "test@user.com"
	})).Return(expectedResp, nil)

	result, err := connector.GetLoginParams(ctx, model.LoginStart{
		Login:       "test@user.com",
		ClientNonce: []byte("client-nonce"),
	})

	require.NoError(t, err)
	assert.Equal(t, "session-123", result.SessionID)
	assert.Equal(t, []byte("salt-root"), result.SaltRoot)
	assert.Equal(t, []byte("server-nonce"), result.ServerNonce)
	mockClient.AssertExpectations(t)
}

func TestConnector_CompleteLogin_Success(t *testing.T) {
	ctx := context.Background()
	mockClient := &MockAuthClient{}
	connector := NewConnector(mockClient)

	params := model.LoginComplete{
		SessionID:   "session-123",
		Login:       "test@user.com",
		ClientNonce: []byte("client-nonce"),
		ServerNonce: []byte("server-nonce"),
		ClientProof: []byte("client-proof"),
	}

	expectedResp := &proto.SessionResult{
		AccessToken:  "access-token",
		RefreshToken: "refresh-token",
	}

	mockClient.On("CompleteLogin", ctx, mock.MatchedBy(func(req *proto.LoginComplete) bool {
		return req.SessionId == params.SessionID && req.Login == params.Login
	})).Return(expectedResp, nil)

	result, err := connector.CompleteLogin(ctx, params)

	require.NoError(t, err)
	assert.Equal(t, "access-token", result.AccessToken)
	assert.Equal(t, "refresh-token", result.RefreshToken)
	mockClient.AssertExpectations(t)
}
