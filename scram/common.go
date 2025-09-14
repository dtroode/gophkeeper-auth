package scram

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"errors"

	"github.com/dtroode/gophkeeper-auth/model"
)

// SCRAM contains KDF parameters and primitives for SCRAM-like protocol.
type SCRAM struct {
	KDFParams model.KDFParams
}

// NewSCRAM creates a new SCRAM with provided KDF parameters.
func NewSCRAM(p model.KDFParams) *SCRAM {
	return &SCRAM{KDFParams: p}
}

// GetKDFParams returns configured KDF parameters.
func (s *SCRAM) GetKDFParams() (model.KDFParams, error) {
	return s.KDFParams, nil
}

// BuildVerifiers builds stored and server verifiers from auth key.
func (s *SCRAM) BuildVerifiers(authKey []byte) (storedKey, serverKey []byte) {
	clientKey := hmacSum(authKey, []byte(model.ClientKeyLabel))
	stored := sha256.Sum256(clientKey)
	server := hmacSum(authKey, []byte(model.ServerKeyLabel))
	return stored[:], server
}

// GenerateNonce creates a random client nonce.
func (s *SCRAM) GenerateNonce() ([]byte, error) {
	clientNonce := make([]byte, 16)
	_, err := rand.Read(clientNonce)
	return clientNonce, err
}

// MakeAuthMessage builds an authentication message from login and nonces.
func (s *SCRAM) MakeAuthMessage(login string, clientNonce, serverNonce []byte) []byte {
	var b bytes.Buffer
	b.WriteString(login)
	b.Write(clientNonce)
	b.Write(serverNonce)
	return b.Bytes()
}

// MakeClientProof builds a client proof from keys and auth message.
func (s *SCRAM) MakeClientProof(authKey []byte, storedKey []byte, authMessage []byte) []byte {
	clientSig := s.MakeClientSignature(storedKey, authMessage)

	clientKey := hmacSum(authKey, []byte(model.ClientKeyLabel))
	proof := make([]byte, len(clientKey))
	for i := range proof {
		proof[i] = clientKey[i] ^ clientSig[i]
	}
	return proof
}

// GenerateSaltRoot returns new random salt root bytes.
func (s *SCRAM) GenerateSaltRoot() ([]byte, error) {
	salt := make([]byte, 32)
	_, err := rand.Read(salt)
	if err != nil {
		return nil, err
	}
	return salt, nil
}

// GenerateServerNonce returns new random server nonce bytes.
func (s *SCRAM) GenerateServerNonce() ([]byte, error) {
	nonce := make([]byte, 16)
	_, err := rand.Read(nonce)
	if err != nil {
		return nil, err
	}
	return nonce, nil
}

// MakeClientSignature computes HMAC-based client signature over auth message.
func (s *SCRAM) MakeClientSignature(storedKey []byte, authMessage []byte) []byte {
	clientSig := hmacSum(storedKey, authMessage)
	return clientSig
}

// DeriveClientKey reconstructs client key from proof and signature.
func (s *SCRAM) DeriveClientKey(clientProof, clientSignature []byte) ([]byte, error) {
	if len(clientProof) != len(clientSignature) {
		return nil, errors.New("client proof and client signature must have the same length")
	}

	clientKey := make([]byte, len(clientProof))
	for i := range clientProof {
		clientKey[i] = clientProof[i] ^ clientSignature[i]
	}

	return clientKey, nil
}

// MakeServerSignature computes server signature over auth message.
func (s *SCRAM) MakeServerSignature(login string, serverKey, clientNonce, serverNonce []byte) []byte {
	authMessage := s.MakeAuthMessage(login, clientNonce, serverNonce)
	return hmacSum(serverKey, authMessage)
}

func hmacSum(key, msg []byte) []byte {
	m := hmac.New(sha256.New, key)
	m.Write(msg)
	return m.Sum(nil)
}
