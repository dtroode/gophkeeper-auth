package scram

import (
	"context"
	"fmt"
	"io"

	"github.com/dtroode/gophkeeper-auth/model"
)

// BaseClientProtocol implements ClientAuth using SCRAM and a server connector.
type BaseClientProtocol struct {
	SCRAM
	cryptoStrategy  model.CryptoStrategy
	serverConnector model.ServerConnector
}

// NewBaseClientProtocol creates a new client protocol with crypto strategy and connector.
func NewBaseClientProtocol(cryptoStrategy model.CryptoStrategy, serverConnector model.ServerConnector) *BaseClientProtocol {
	return &BaseClientProtocol{
		SCRAM:           SCRAM{},
		cryptoStrategy:  cryptoStrategy,
		serverConnector: serverConnector,
	}
}

// RegisterUser performs registration: derives keys, builds verifiers and completes on server.
func (p *BaseClientProtocol) RegisterUser(ctx context.Context, params model.RegisterRequest) (model.RegResult, error) {
	serverParams, err := p.serverConnector.GetRegParams(ctx, params.Login)
	if err != nil {
		return model.RegResult{}, fmt.Errorf("failed to start registration")
	}

	rootKey := p.cryptoStrategy.DeriveRootKey(
		[]byte(params.Password),
		serverParams.KDFParams,
		serverParams.SaltRoot,
	)

	authKey, masterKey, err := p.splitKeys(rootKey)
	if err != nil {
		return model.RegResult{}, fmt.Errorf("failed to split keys: %w", err)
	}

	storedKey, serverKey := p.BuildVerifiers(authKey)

	err = p.serverConnector.CompleteReg(ctx, model.RegComplete{
		UserData:  params.UserData,
		SessionID: serverParams.SessionID,
		Login:     params.Login,
		SaltRoot:  serverParams.SaltRoot,
		KDF:       serverParams.KDFParams,
		StoredKey: storedKey,
		ServerKey: serverKey,
	})
	if err != nil {
		return model.RegResult{}, fmt.Errorf("failed to finish registration: %w", err)
	}

	return model.RegResult{
		AuthKey:   authKey,
		MasterKey: masterKey,
	}, nil
}

// LoginUser performs login: derives keys, builds proof, and completes login on server.
func (p *BaseClientProtocol) LoginUser(ctx context.Context, params model.LoginRequest) (model.LoginResult, error) {
	nonce, err := p.GenerateNonce()
	if err != nil {
		return model.LoginResult{}, fmt.Errorf("failed to generate client nonce: %w", err)
	}

	serverParams, err := p.serverConnector.GetLoginParams(ctx, model.LoginStart{
		Login:       params.Login,
		ClientNonce: nonce,
	})
	if err != nil {
		return model.LoginResult{}, fmt.Errorf("failed to start login: %w", err)
	}

	rootKey := p.cryptoStrategy.DeriveRootKey(
		[]byte(params.Password),
		serverParams.KDFParams,
		serverParams.SaltRoot,
	)

	authKey, masterKey, err := p.splitKeys(rootKey)
	if err != nil {
		return model.LoginResult{}, fmt.Errorf("failed to split keys: %w", err)
	}

	storedKey, _ := p.BuildVerifiers(authKey)
	authMessage := p.MakeAuthMessage(params.Login, nonce, serverParams.ServerNonce)
	clientProof := p.MakeClientProof(authKey, storedKey, authMessage)

	resp, err := p.serverConnector.CompleteLogin(ctx, model.LoginComplete{
		SessionID:   serverParams.SessionID,
		Login:       params.Login,
		ClientNonce: nonce,
		ServerNonce: serverParams.ServerNonce,
		ClientProof: clientProof,
	})
	if err != nil {
		return model.LoginResult{}, fmt.Errorf("failed to finish login: %w", err)
	}

	return model.LoginResult{
		MasterKey:    masterKey,
		AccessToken:  resp.AccessToken,
		RefreshToken: resp.RefreshToken,
	}, nil
}

func (p *BaseClientProtocol) splitKeys(rootKey []byte) (authKey, masterKey []byte, err error) {
	keys, err := p.cryptoStrategy.SplitKeys(rootKey, model.AuthLabel, model.MKLabel)

	hAuth := keys[0]
	hMK := keys[1]

	authKey = make([]byte, 32)
	masterKey = make([]byte, 32)
	if _, err := io.ReadFull(hAuth, authKey); err != nil {
		return nil, nil, fmt.Errorf("failed to read auth key: %w", err)
	}
	if _, err := io.ReadFull(hMK, masterKey); err != nil {
		return nil, nil, fmt.Errorf("failed to read master key: %w", err)
	}

	return authKey, masterKey, nil
}
