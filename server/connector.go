package api

import (
	"context"
	"fmt"

	"github.com/dtroode/gophkeeper-auth/model"
	"github.com/dtroode/gophkeeper-auth/server/proto"
)

// Connector implements ServerConnector over gRPC client.
type Connector struct {
	client proto.AuthClient
}

// NewConnector creates a new Connector with provided gRPC client.
func NewConnector(client proto.AuthClient) *Connector {
	return &Connector{client: client}
}

// GetRegParams requests registration parameters from the server.
func (s *Connector) GetRegParams(ctx context.Context, login string) (model.RegParams, error) {
	resp, err := s.client.GetRegParams(ctx, &proto.RegStart{
		Login: login,
	})
	if err != nil {
		return model.RegParams{}, fmt.Errorf("failed to obtain server registration params")
	}

	return model.RegParams{
		SessionID: resp.SessionId,
		KDFParams: model.KDFParams{
			MemKiB: resp.KdfParams.MemKib,
			Time:   resp.KdfParams.Time,
			Par:    uint8(resp.KdfParams.Par),
		},
		SaltRoot: resp.SaltRoot,
	}, nil
}

// CompleteReg sends registration verifiers to the server.
func (s *Connector) CompleteReg(ctx context.Context, params model.RegComplete) error {
	_, err := s.client.CompleteReg(ctx, &proto.RegComplete{
		SessionId: params.SessionID,
		Login:     params.Login,
		SaltRoot:  params.SaltRoot,
		KdfParams: &proto.KDFParams{
			MemKib: params.KDF.MemKiB,
			Time:   params.KDF.Time,
			Par:    uint32(params.KDF.Par),
		},
		StoredKey: params.StoredKey,
		ServerKey: params.ServerKey,
	})

	if err != nil {
		return fmt.Errorf("failed to register user")
	}

	return nil
}

// GetLoginParams requests login parameters from the server.
func (s *Connector) GetLoginParams(ctx context.Context, params model.LoginStart) (model.LoginParams, error) {
	resp, err := s.client.GetLoginParams(ctx, &proto.LoginStart{
		Login:       params.Login,
		ClientNonce: params.ClientNonce,
	})
	if err != nil {
		return model.LoginParams{}, fmt.Errorf("failed to obtain server login params")
	}

	return model.LoginParams{
		SessionID: resp.SessionId,
		KDFParams: model.KDFParams{
			MemKiB: resp.KdfParams.MemKib,
			Time:   resp.KdfParams.Time,
			Par:    uint8(resp.KdfParams.Par),
		},
		SaltRoot:    resp.SaltRoot,
		ServerNonce: resp.ServerNonce,
	}, nil
}

// CompleteLogin finalizes login and returns session tokens from the server.
func (s *Connector) CompleteLogin(ctx context.Context, params model.LoginComplete) (model.SessionResult, error) {
	resp, err := s.client.CompleteLogin(ctx, &proto.LoginComplete{
		SessionId:   params.SessionID,
		Login:       params.Login,
		ClientNonce: params.ClientNonce,
		ServerNonce: params.ServerNonce,
		ClientProof: params.ClientProof,
	})
	if err != nil {
		return model.SessionResult{}, fmt.Errorf("failed to complete login")
	}

	return model.SessionResult{
		ServerSignature: resp.ServerSignature,
		AccessToken:     resp.AccessToken,
		RefreshToken:    resp.RefreshToken,
	}, nil
}
