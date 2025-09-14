package scram

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"time"

	apiErrors "github.com/dtroode/gophkeeper-api/errors"
	"github.com/dtroode/gophkeeper-auth/model"
	"github.com/google/uuid"
)

type Logger interface {
	Info(msg string, args ...any)
	Error(msg string, args ...any)
	Debug(msg string, args ...any)
}

type BaseServerProtocol struct {
	*SCRAM
	logger Logger
}

func NewBaseServerProtocol(kdf model.KDFParams, logger Logger) *BaseServerProtocol {
	scram := NewSCRAM(kdf)
	return &BaseServerProtocol{
		SCRAM:  scram,
		logger: logger,
	}
}

func (p *BaseServerProtocol) PrepareRegistration(ctx context.Context) (model.RegParams, error) {
	kdfParams, err := p.GetKDFParams()
	if err != nil {
		return model.RegParams{}, fmt.Errorf("failed to get kdf params: %w", err)
	}

	saltRoot, err := p.GenerateSaltRoot()
	if err != nil {
		return model.RegParams{}, fmt.Errorf("failed to generate salt root: %w", err)
	}

	sessionID := uuid.New()

	return model.RegParams{
		SessionID: sessionID.String(),
		KDFParams: kdfParams,
		SaltRoot:  saltRoot,
	}, nil
}

func (p *BaseServerProtocol) VerifyRegistration(ctx context.Context, pendingReg model.PendingReg, params model.RegComplete) error {
	if pendingReg.Consumed {
		return apiErrors.NewErrSignup()
	}

	if pendingReg.ExpiresAt.Before(time.Now()) {
		return apiErrors.NewErrSignup()
	}

	if pendingReg.Login != params.Login {
		return apiErrors.NewErrSignup()
	}

	if subtle.ConstantTimeCompare(pendingReg.SaltRoot, params.SaltRoot) == 0 {
		return apiErrors.NewErrSignup()
	}

	if len(params.StoredKey) != 32 || len(params.ServerKey) != 32 {
		return apiErrors.NewErrSignup()
	}

	marshaledKDF, err := json.Marshal(params.KDF)
	if err != nil {
		return fmt.Errorf("failed to marshal kdf: %w", err)
	}

	if subtle.ConstantTimeCompare(pendingReg.KDF, marshaledKDF) == 0 {
		return apiErrors.NewErrSignup()
	}

	return nil
}

func (p *BaseServerProtocol) PrepareLogin(ctx context.Context) (model.LoginParams, error) {
	nonce, err := p.GenerateServerNonce()
	if err != nil {
		return model.LoginParams{}, fmt.Errorf("failed to generate server nonce: %w", err)
	}

	sessionID := uuid.NewString()

	return model.LoginParams{
		SessionID:   sessionID,
		ServerNonce: nonce,
	}, nil
}

func (p *BaseServerProtocol) VerifyLogin(ctx context.Context, storedKey []byte, pendingLogin model.PendingLogin, params model.LoginComplete) error {
	p.logger.Debug("Verifying login", "pendingLogin", pendingLogin, "params", params)
	if pendingLogin.Consumed {
		p.logger.Error("Login already consumed", "pendingLogin", pendingLogin, "params", params)
		return apiErrors.NewErrLogin()
	}

	if pendingLogin.ExpiresAt.Before(time.Now()) {
		p.logger.Error("Login expired", "pendingLogin", pendingLogin, "params", params)
		return apiErrors.NewErrLogin()
	}

	if pendingLogin.Login != params.Login {
		p.logger.Error("Login login mismatch", "pendingLogin", pendingLogin, "params", params)
		return apiErrors.NewErrLogin()
	}

	authMessage := p.MakeAuthMessage(params.Login, params.ClientNonce, params.ServerNonce)

	clientSig := p.MakeClientSignature(storedKey, authMessage)

	clientKey, err := p.DeriveClientKey(params.ClientProof, clientSig)
	if err != nil {
		return fmt.Errorf("failed to derive client key: %w", err)
	}

	computedStoredKey := sha256.Sum256(clientKey)

	if subtle.ConstantTimeCompare(computedStoredKey[:], storedKey) != 1 {
		return fmt.Errorf("invalid login params")
	}

	if subtle.ConstantTimeCompare(pendingLogin.ClientNonce, params.ClientNonce) != 1 {
		return fmt.Errorf("invalid client nonce")
	}

	return nil
}
