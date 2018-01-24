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
		{"$argon2i$v=19$m=65536,t=2,p=4$c29tZXNhbHQ$IMit9qkFULCMA/ViizL57cnTLOa5DiVM9eMwpAvPwr4",
			"argon2i", crypt.Parameter{"v": "19", "m": "65536", "t": "2", "p": "4"}, "c29tZXNhbHQ", "IMit9qkFULCMA/ViizL57cnTLOa5DiVM9eMwpAvPwr4", nil},
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
