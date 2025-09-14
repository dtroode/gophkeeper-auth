package model

import "io"

// KeyDerivator derives a root key from password and KDF params.
type KeyDerivator interface {
	DeriveRootKey(password []byte, p KDFParams, saltRoot []byte) []byte
}

// KeySplitter splits a root key into multiple independent key streams.
type KeySplitter interface {
	SplitKeys(rootKey []byte, lables ...string) ([]io.Reader, error)
}

// CryptoStrategy groups key derivation and key splitting for protocols.
type CryptoStrategy interface {
	KeyDerivator
	KeySplitter
}
