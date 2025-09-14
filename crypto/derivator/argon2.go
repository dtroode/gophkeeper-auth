package derivator

import (
	"github.com/dtroode/gophkeeper-auth/model"

	"golang.org/x/crypto/argon2"
)

// Argon2Derivator derives root keys using Argon2id.
type Argon2Derivator struct{}

// NewArgon2Derivator creates a new Argon2Derivator.
func NewArgon2Derivator() *Argon2Derivator {
	return &Argon2Derivator{}
}

// DeriveRootKey derives a 32-byte root key from password and salt using KDF params.
func (a *Argon2Derivator) DeriveRootKey(password []byte, p model.KDFParams, saltRoot []byte) []byte {
	return argon2.IDKey(password, saltRoot, p.Time, p.MemKiB, p.Par, 32)
}
