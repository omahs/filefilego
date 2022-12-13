package block

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestIsValidVerifier(t *testing.T) {
	assert.True(t, IsValidVerifier(BlockVerifiers[0].Address))
	assert.False(t, IsValidVerifier(""))
}
