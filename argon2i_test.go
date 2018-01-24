package crypt_test

import (
	"testing"

	"github.com/simia-tech/crypt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestArgon2i(t *testing.T) {
	tcs := []struct {
		password       string
		settings       string
		expectedResult string
		expectedErr    error
	}{
		{"password", "$argon2i$v=19$m=65536,t=2,p=4$c29tZXNhbHQ", "$argon2i$v=19$m=65536,t=2$c29tZXNhbHQ$IMit9qkFULCMA/ViizL57cnTLOa5DiVM9eMwpAvPwr4", nil},
		{"another password", "$argon2i$v=19$m=65536,t=2,p=4$YW5vdGhlcnNhbHQ", "$argon2i$v=19$m=65536,t=2$YW5vdGhlcnNhbHQ$BCRltpeTFX0QYrELiOXWGZniID9nOUsBPy8Bu0SE7bM", nil},
		{"password", "$argon2i$v=19$m=65536,t=2,p=4$bG9uZ3NhbHRsb25nc2FsdGxvbmc", "$argon2i$v=19$m=65536,t=2$bG9uZ3NhbHRsb25nc2FsdGxvbmc$rDmQABiNkSO3bGHbBUkShgb7wIlBP8HHfq6nDH+Sqss", nil},
	}

	for _, tc := range tcs {
		t.Run(tc.settings, func(t *testing.T) {
			result, err := crypt.Crypt(tc.password, tc.settings)
			require.Equal(t, tc.expectedErr, err)
			assert.Equal(t, tc.expectedResult, result)
		})
	}
}
