package splitter

import (
	"io"
	"testing"

	"github.com/stretchr/testify/require"
)

func readN(t *testing.T, r io.Reader, n int) []byte {
	b := make([]byte, n)
	_, err := io.ReadFull(r, b)
	require.NoError(t, err)
	return b
}

func TestHKDFSplitter_SplitKeys_DeterministicAndDistinct(t *testing.T) {
	s := NewHKDFSplitter()
	root := []byte("root-key")

	readers1, err := s.SplitKeys(root, "a", "b")
	require.NoError(t, err)
	readers2, err := s.SplitKeys(root, "a", "b")
	require.NoError(t, err)

	a1 := readN(t, readers1[0], 32)
	b1 := readN(t, readers1[1], 32)
	a2 := readN(t, readers2[0], 32)
	b2 := readN(t, readers2[1], 32)

	require.Equal(t, a1, a2)
	require.Equal(t, b1, b2)
	require.NotEqual(t, a1, b1)
}
