package crypt_test

import (
	"testing"

	"github.com/simia-tech/crypt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDecodeSettings(t *testing.T) {
	tcs := []struct {
		settings   string
		expectCode string
		expectSalt string
		expectHash string
		expectErr  error
	}{
		{"$1$$", "1", "", "", nil},
		{"$1$salt$", "1", "salt", "", nil},
		{"$1$salt$hash", "1", "salt", "hash", nil},
		{"$1$salt$hash$", "1", "salt", "hash", nil},
	}

	for _, tc := range tcs {
		t.Run(tc.settings, func(t *testing.T) {
			code, salt, hash, err := crypt.DecodeSettings(tc.settings)
			require.Equal(t, tc.expectErr, err)
			assert.Equal(t, tc.expectCode, code)
			assert.Equal(t, tc.expectSalt, salt)
			assert.Equal(t, tc.expectHash, hash)
		})
	}
}
