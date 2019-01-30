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
	tcs := []struct {
		password       string
		settings       string
		expectedResult string
		expectedErr    error
	}{
		{"generate salt", "$argon2i$v=19$m=65536,t=2,p=4$", "$argon2i$v=19$m=65536,t=2$", nil},
		{"password", "$argon2i$v=19$m=65536,t=2,p=4$c29tZXNhbHQ", "$argon2i$v=19$m=65536,t=2$c29tZXNhbHQ$IMit9qkFULCMA/ViizL57cnTLOa5DiVM9eMwpAvPwr4", nil},
		{"another password", "$argon2i$v=19$m=65536,t=2,p=4$YW5vdGhlcnNhbHQ", "$argon2i$v=19$m=65536,t=2$YW5vdGhlcnNhbHQ$BCRltpeTFX0QYrELiOXWGZniID9nOUsBPy8Bu0SE7bM", nil},
		{"password", "$argon2i$v=19$m=65536,t=2,p=1$bG9uZ3NhbHRsb25nc2FsdGxvbmc", "$argon2i$v=19$m=65536,t=2,p=1$bG9uZ3NhbHRsb25nc2FsdA$8BZnxCqANQ3mGYITjgezarZ/b5vivfVRVy3cWwwXGHI", nil},
		{"ignore-hash-in-settings", "$argon2i$v=19$m=65536,t=2$bG9uZ3NhbHRsb25nc2FsdGxvbmc$rDmQABiNkSO3bGHbBUkShgb7wIlBP8HHfq6nDH+Sqss", "$argon2i$v=19$m=65536,t=2$bG9uZ3NhbHRsb25nc2FsdA$Cfa1JVLA/wGtR7UeWI+Q+ZOfMmyPchePKy2h+kjryG8", nil},
		{"password", "$argon2i$v=19$m=65536,t=3,p=1$bG9uZ3NhbHRsb25nc2FsdA", "$argon2i$v=19$m=65536,t=3,p=1$bG9uZ3NhbHRsb25nc2FsdA$K2rLfVoQG17LuUn26otasTX1WBXjr6hi5NZXKKxmYrs", nil},
	}

	for _, tc := range tcs {
		t.Run(tc.settings, func(t *testing.T) {
			result, err := crypt.Crypt(tc.password, tc.settings)
			require.Equal(t, tc.expectedErr, err)
			assert.True(t, strings.HasPrefix(result, tc.expectedResult), "expected prefix %q, got %q", tc.expectedResult, result)
		})
	}
}

func TestArgon2iSettings(t *testing.T) {
	tcs := []struct {
		m                      int
		t                      int
		p                      int
		expectedSettingsPrefix string
	}{
		{65536, 2, 4, "$argon2i$v=19$m=65536,t=2,p=4"},
	}

	for _, tc := range tcs {
		t.Run(fmt.Sprintf("m=%d,t=%d,p=%d", tc.m, tc.t, tc.p), func(t *testing.T) {
			settings, err := crypt.Argon2iSettings(tc.m, tc.t, tc.p)
			require.NoError(t, err)
			assert.True(t, strings.HasPrefix(settings, tc.expectedSettingsPrefix))
		})
	}
}
