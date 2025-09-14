package model

import (
	"context"
	"time"
)

// ClientAuth defines client-side authentication protocol.
type ClientAuth interface {
	RegisterUser(ctx context.Context, params RegisterRequest) (RegResult, error)
	LoginUser(ctx context.Context, params LoginRequest) (LoginResult, error)
}

// ServerAuth defines server-side authentication protocol.
type ServerAuth interface {
	PrepareRegistration(ctx context.Context) (RegParams, error)
	VerifyRegistration(ctx context.Context, pendingReg PendingReg, params RegComplete) error
	PrepareLogin(ctx context.Context) (LoginParams, error)
	VerifyLogin(ctx context.Context, storedKey []byte, pendingLogin PendingLogin, params LoginComplete) error
	MakeServerSignature(login string, serverKey, clientNonce, serverNonce []byte) []byte
}

// ServerConnector defines transport to the auth server for client protocol.
type ServerConnector interface {
	GetRegParams(ctx context.Context, login string) (RegParams, error)
	CompleteReg(ctx context.Context, params RegComplete) error
	GetLoginParams(ctx context.Context, params LoginStart) (LoginParams, error)
	CompleteLogin(ctx context.Context, params LoginComplete) (SessionResult, error)
}

// LoginStart is the initial login request payload.
type LoginStart struct {
	Login       string
	ClientNonce []byte
}

// SessionParams contains common session identifiers and nonces.
type SessionParams struct {
	SessionID   string
	ServerNonce []byte
}

// LoginParams contains data required to compute proofs during login.
type LoginParams struct {
	SessionID   string
	KDFParams   KDFParams
	SaltRoot    []byte
	ServerNonce []byte
}

// SessionResult contains tokens and signatures resulting from login.
type SessionResult struct {
	ServerSignature []byte
	AccessToken     string
	RefreshToken    string
}

// UserData holds optional user profile information used at registration.
type UserData struct {
	FirstName string
	LastName  string
}

// RegisterRequest contains registration parameters.
type RegisterRequest struct {
	UserData
	Login    string
	Password string
}

// RegResult contains derived keys from registration.
type RegResult struct {
	AuthKey   []byte
	MasterKey []byte
}

// LoginRequest contains credentials for login.
type LoginRequest struct {
	Login    string
	Password string
}

// LoginResult contains master key and tokens from a successful login.
type LoginResult struct {
	MasterKey    []byte
	AccessToken  string
	RefreshToken string
}

// RegParams contains KDF parameters and salt for registration.
type RegParams struct {
	SessionID string
	KDFParams KDFParams
	SaltRoot  []byte
}

// RegComplete completes registration with verifiers.
type RegComplete struct {
	UserData
	SessionID string
	Login     string
	SaltRoot  []byte
	KDF       KDFParams
	StoredKey []byte
	ServerKey []byte
}

// LoginComplete finalizes login by sending client proof.
type LoginComplete struct {
	SessionID   string
	Login       string
	ClientNonce []byte
	ServerNonce []byte
	ClientProof []byte
}

// PendingReg tracks a prepared registration session.
type PendingReg struct {
	SessionID string
	Login     string
	SaltRoot  []byte
	KDF       []byte
	ExpiresAt time.Time
	Consumed  bool
}

// PendingLogin tracks a prepared login session.
type PendingLogin struct {
	SessionID   string
	Login       string
	ClientNonce []byte
	ServerNonce []byte
	ExpiresAt   time.Time
	Consumed    bool
}
