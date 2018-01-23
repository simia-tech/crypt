package crypt_test

import (
	"testing"

	"github.com/simia-tech/crypt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDecodeSettings(t *testing.T) {
	tcs := []struct {
		settings        string
		expectCode      string
		expectParameter crypt.Parameter
		expectSalt      string
		expectHash      string
		expectErr       error
	}{
		{"$1$$", "1", nil, "", "", nil},
		{"$1$salt$", "1", nil, "salt", "", nil},
		{"$1$salt$hash", "1", nil, "salt", "hash", nil},
		{"$1$rounds=100$salt", "1", crypt.Parameter{"rounds": "100"}, "salt", "", nil},
		{"$1$rounds=200$salt$hash", "1", crypt.Parameter{"rounds": "200"}, "salt", "hash", nil},
		{"$1$rounds=300$salt$hash$", "1", crypt.Parameter{"rounds": "300"}, "salt", "hash", nil},
	}

	for _, tc := range tcs {
		t.Run(tc.settings, func(t *testing.T) {
			code, parameter, salt, hash, err := crypt.DecodeSettings(tc.settings)
			require.Equal(t, tc.expectErr, err)
			assert.Equal(t, tc.expectCode, code)
			assert.Equal(t, tc.expectParameter, parameter)
			assert.Equal(t, tc.expectSalt, salt)
			assert.Equal(t, tc.expectHash, hash)
		})
	}
}
