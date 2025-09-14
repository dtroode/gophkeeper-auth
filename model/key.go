package model

const (
	// AuthLabel is HKDF label for authentication key derivation.
	AuthLabel = "gk/auth"
	// MKLabel is HKDF label for master key derivation.
	MKLabel = "gk/mk"
	// ClientKeyLabel is HMAC label for client key.
	ClientKeyLabel = "Client Key"
	// ServerKeyLabel is HMAC label for server key.
	ServerKeyLabel = "Server Key"
)
