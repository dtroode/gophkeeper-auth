package splitter

import (
	"crypto/sha256"
	"io"

	"golang.org/x/crypto/hkdf"
)

// HKDFSplitter splits a root key into independent streams using HKDF-SHA256.
type HKDFSplitter struct{}

// NewHKDFSplitter creates a new HKDFSplitter.
func NewHKDFSplitter() *HKDFSplitter {
	return &HKDFSplitter{}
}

// SplitKeys returns HKDF readers derived from the rootKey using provided labels.
func (h *HKDFSplitter) SplitKeys(rootKey []byte, lables ...string) ([]io.Reader, error) {
	parts := make([]io.Reader, 0, len(lables))

	for _, label := range lables {
		parts = append(parts, hkdf.New(sha256.New, rootKey, nil, []byte(label)))
	}

	return parts, nil
}
