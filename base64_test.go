// Copyright 2018 Philipp Brüll (pb@simia.tech)
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package crypt_test

import (
	"testing"

	"github.com/simia-tech/crypt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBase64(t *testing.T) {
	testFn := func(decoded, encoded string) (string, func(*testing.T)) {
		return decoded, func(t *testing.T) {
			encodeResult := crypt.Base64Encoding.EncodeToString([]byte(decoded))
			assert.Equal(t, encoded, encodeResult)

			decodeResult, err := crypt.Base64Encoding.DecodeString(string(encodeResult))
			require.NoError(t, err)
			assert.Equal(t, decoded, string(decodeResult))
		}
	}

	t.Run(testFn("somesalt", "c29tZXNhbHQ"))
	t.Run(testFn("test", "dGVzdA"))
	t.Run(testFn("test123test123", "dGVzdDEyM3Rlc3QxMjM"))
}

func TestEncode24BitBase64(t *testing.T) {
	testFn := func(decoded, expectEncoded string) (string, func(*testing.T)) {
		return decoded, func(t *testing.T) {
			encodeResult := crypt.Encode24BitBase64([]byte(decoded))
			assert.Equal(t, expectEncoded, string(encodeResult))
		}
	}

	t.Run(testFn("somesalt", "nxKPZBLMgF5"))
	t.Run(testFn("test", "oJqQo/"))
	t.Run(testFn("test123test123", "oJqQo3XAnELNnFLAmA1"))
}
