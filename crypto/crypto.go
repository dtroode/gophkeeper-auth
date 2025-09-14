package auth

import (
	"github.com/dtroode/gophkeeper-auth/crypto/derivator"
	"github.com/dtroode/gophkeeper-auth/crypto/splitter"
	"github.com/dtroode/gophkeeper-auth/model"
)

// CryptoStrategy composes key derivation and key splitting implementations.
type CryptoStrategy struct {
	model.KeyDerivator
	model.KeySplitter
}

// NewCryptoStrategy creates a default crypto strategy using Argon2 and HKDF.
func NewCryptoStrategy() model.CryptoStrategy {
	return &CryptoStrategy{
		KeyDerivator: derivator.NewArgon2Derivator(),
		KeySplitter:  splitter.NewHKDFSplitter(),
	}
}
