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

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/simia-tech/crypt"
)

func TestSettings(t *testing.T) {
	testFn := func(hash, expectSettings string) (string, func(*testing.T)) {
		return hash, func(t *testing.T) {
			settings := crypt.Settings(hash)
			assert.Equal(t, expectSettings, settings)
		}
	}

	t.Run(testFn("$1$$", "$1$"))
	t.Run(testFn("$1$salt$", "$1$salt"))
	t.Run(testFn("$1$salt$hash", "$1$salt"))
	t.Run(testFn("$1$rounds=100$salt", "$1$rounds=100$salt"))
	t.Run(testFn("$1$rounds=200$salt$hash", "$1$rounds=200$salt"))
	t.Run(testFn("$1$rounds=300$salt$hash$", "$1$rounds=300$salt"))
	t.Run(testFn("$2a$08$ybX1Hjkb5N.8WEcYtBuB7u", "$2a$08$ybX1Hjkb5N.8WEcYtBuB7u"))
	t.Run(testFn("$2a$08$ybX1Hjkb5N.8WEcYtBuB7u$CMA/ViizL57cnTLOa5DiVM9e", "$2a$08$ybX1Hjkb5N.8WEcYtBuB7u"))
	t.Run(testFn("$argon2i$v=19$m=65536,t=2,p=4$c29tZXNhbHQ$IMit9qkFULCMA/ViizL57cnTLOa5DiVM9eMwpAvPwr4", "$argon2i$v=19$m=65536,t=2,p=4$c29tZXNhbHQ"))
	t.Run(testFn("$argon2i$v=19$m=65536,t=2,p=4,k=64$c29tZXNhbHQ$IMit9qkFULCMA/ViizL57cnTLOa5DiVM9eMwpAvPwr4", "$argon2i$v=19$m=65536,t=2,p=4,k=64$c29tZXNhbHQ"))
}

func TestDecodeSettings(t *testing.T) {
	testFn := func(settings, expectCode string, expectParameter crypt.Parameter, expectSalt, expectHash string, expectErr error) (string, func(*testing.T)) {
		return settings, func(t *testing.T) {
			code, parameter, salt, hash, err := crypt.DecodeSettings(settings)
			require.Equal(t, expectErr, err)
			assert.Equal(t, expectCode, code)
			assert.Equal(t, expectParameter, parameter)
			assert.Equal(t, expectSalt, salt)
			assert.Equal(t, expectHash, hash)
		}
	}

	t.Run(testFn("$1$$", "1", nil, "", "", nil))
	t.Run(testFn("$1$salt$", "1", nil, "salt", "", nil))
	t.Run(testFn("$1$salt$hash", "1", nil, "salt", "hash", nil))
	t.Run(testFn("$1$rounds=100$salt", "1", crypt.Parameter{"rounds": "100"}, "salt", "", nil))
	t.Run(testFn("$1$rounds=200$salt$hash", "1", crypt.Parameter{"rounds": "200"}, "salt", "hash", nil))
	t.Run(testFn("$1$rounds=300$salt$hash$", "1", crypt.Parameter{"rounds": "300"}, "salt", "hash", nil))
	t.Run(testFn("$2a$08$ybX1Hjkb5N.8WEcYtBuB7u", "2a", crypt.Parameter{"cost": "8"}, "ybX1Hjkb5N.8WEcYtBuB7u", "", nil))
	t.Run(testFn("$argon2i$v=19$m=65536,t=2,p=4$c29tZXNhbHQ$IMit9qkFULCMA/ViizL57cnTLOa5DiVM9eMwpAvPwr4", "argon2i", crypt.Parameter{"v": "19", "m": "65536", "t": "2", "p": "4"}, "c29tZXNhbHQ", "IMit9qkFULCMA/ViizL57cnTLOa5DiVM9eMwpAvPwr4", nil))
	t.Run(testFn("$argon2i$v=19$m=65536,t=2,p=4,k=64$c29tZXNhbHQ$IMit9qkFULCMA/ViizL57cnTLOa5DiVM9eMwpAvPwr4", "argon2i", crypt.Parameter{"v": "19", "m": "65536", "t": "2", "p": "4", "k": "64"}, "c29tZXNhbHQ", "IMit9qkFULCMA/ViizL57cnTLOa5DiVM9eMwpAvPwr4", nil))
}
