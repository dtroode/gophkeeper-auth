package model

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewKDFParams(t *testing.T) {
	params := NewKDFParams(1, 1024, 2)

	assert.Equal(t, uint32(1), params.Time)
	assert.Equal(t, uint32(1024), params.MemKiB)
	assert.Equal(t, uint8(2), params.Par)
}

func TestKDFParams_ZeroValues(t *testing.T) {
	params := NewKDFParams(0, 0, 0)

	assert.Equal(t, uint32(0), params.Time)
	assert.Equal(t, uint32(0), params.MemKiB)
	assert.Equal(t, uint8(0), params.Par)
}

func TestKDFParams_MaxValues(t *testing.T) {
	params := NewKDFParams(4294967295, 4294967295, 255)

	assert.Equal(t, uint32(4294967295), params.Time)
	assert.Equal(t, uint32(4294967295), params.MemKiB)
	assert.Equal(t, uint8(255), params.Par)
}
