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
	"fmt"
	"strings"
	"testing"

	"github.com/simia-tech/crypt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestArgon2i(t *testing.T) {
	testFn := func(password, settings, expectResult string, expectErr error) (string, func(*testing.T)) {
		return settings, func(t *testing.T) {
			result, err := crypt.Crypt(password, settings)
			require.Equal(t, expectErr, err)
			assert.True(t, strings.HasPrefix(result, expectResult), "expected prefix %q, got %q", expectResult, result)
		}
	}

	t.Run(testFn("generate salt", "$argon2i$v=19$m=65536,t=2,p=4$",
		"$argon2i$v=19$m=65536,t=2$", nil))
	t.Run(testFn("password", "$argon2i$v=19$m=65536,t=2,p=4$c29tZXNhbHQ",
		"$argon2i$v=19$m=65536,t=2$c29tZXNhbHQ$IMit9qkFULCMA/ViizL57cnTLOa5DiVM9eMwpAvPwr4", nil))
	t.Run(testFn("another password", "$argon2i$v=19$m=65536,t=2,p=4$YW5vdGhlcnNhbHQ",
		"$argon2i$v=19$m=65536,t=2$YW5vdGhlcnNhbHQ$BCRltpeTFX0QYrELiOXWGZniID9nOUsBPy8Bu0SE7bM", nil))
	t.Run(testFn("password", "$argon2i$v=19$m=65536,t=2,p=1$bG9uZ3NhbHRsb25nc2FsdGxvbmc",
		"$argon2i$v=19$m=65536,t=2,p=1$bG9uZ3NhbHRsb25nc2FsdGxvbmc$N2zfK+oCIRMbTX04zZS4X2uLKX3SK0KkNxyCw/NURrU", nil))
	t.Run(testFn("ignore-hash-in-settings", "$argon2i$v=19$m=65536,t=2$bG9uZ3NhbHRsb25nc2FsdGxvbmc$rDmQABiNkSO3bGHbBUkShgb7wIlBP8HHfq6nDH+Sqss",
		"$argon2i$v=19$m=65536,t=2$bG9uZ3NhbHRsb25nc2FsdGxvbmc$xY9IRFH+zQduVUYoZfSoT6tylET3/AUIOMS3rFF0x0o", nil))
	t.Run(testFn("password", "$argon2i$v=19$m=65536,t=3,p=1$bG9uZ3NhbHRsb25nc2FsdA",
		"$argon2i$v=19$m=65536,t=3,p=1$bG9uZ3NhbHRsb25nc2FsdA$K2rLfVoQG17LuUn26otasTX1WBXjr6hi5NZXKKxmYrs", nil))
	t.Run(testFn("password", "$argon2i$v=19$m=65536,t=3,p=1,k=64$bG9uZ3NhbHRsb25nc2FsdA",
		"$argon2i$v=19$m=65536,t=3,p=1,k=64$bG9uZ3NhbHRsb25nc2FsdA$7DnJ2B7gxZDMEk+HVNDpIuTtOxDkwDaA0IhvuiBn9oeBTXpqBPxP9iro2cPiFongTwoFHHpVrqiL8JvMXrb63Q", nil))
}

func TestArgon2iSettings(t *testing.T) {
	testFn := func(m, t, p, k int, expectSettingsPrefix string) (string, func(*testing.T)) {
		return fmt.Sprintf("m=%d,t=%d,p=%d,k=%d", m, t, p, k), func(tt *testing.T) {
			settings, err := crypt.Argon2iSettings(m, t, p, k)
			require.NoError(tt, err)
			assert.True(tt, strings.HasPrefix(settings, expectSettingsPrefix))
		}
	}

	t.Run(testFn(65536, 2, 4, 64, "$argon2i$v=19$m=65536,t=2,p=4,k=64"))
}
