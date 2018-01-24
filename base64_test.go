package crypt_test

import (
	"testing"

	"github.com/simia-tech/crypt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBase64(t *testing.T) {
	tcs := []struct {
		decoded string
		encoded string
	}{
		{"somesalt", "c29tZXNhbHQ"},
		{"test", "dGVzdA"},
		{"test123test123", "dGVzdDEyM3Rlc3QxMjM"},
	}

	for _, tc := range tcs {
		t.Run(tc.decoded, func(t *testing.T) {
			encodeResult := crypt.Base64Encoding.EncodeToString([]byte(tc.decoded))
			assert.Equal(t, tc.encoded, encodeResult)

			decodeResult, err := crypt.Base64Encoding.DecodeString(string(encodeResult))
			require.NoError(t, err)
			assert.Equal(t, tc.decoded, string(decodeResult))
		})
	}
}

func TestEncode24BitBase64(t *testing.T) {
	tcs := []struct {
		decoded       string
		expectEncoded string
	}{
		{"somesalt", "nxKPZBLMgF5"},
		{"test", "oJqQo/"},
		{"test123test123", "oJqQo3XAnELNnFLAmA1"},
	}

	for _, tc := range tcs {
		t.Run(tc.decoded, func(t *testing.T) {
			encodeResult := crypt.Encode24BitBase64([]byte(tc.decoded))
			assert.Equal(t, tc.expectEncoded, string(encodeResult))
		})
	}
}
