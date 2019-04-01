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

func TestArgon2id(t *testing.T) {
	tcs := []struct {
		password       string
		settings       string
		expectedResult string
		expectedErr    error
	}{
		{
			"generate salt",
			"$argon2id$v=19$m=65536,t=2,p=4$",
			"$argon2id$v=19$m=65536,t=2,p=4$",
			nil,
		},
		{
			"password", // salt = somesalt
			"$argon2id$v=19$m=65536,t=2,p=4$c29tZXNhbHQ",
			"$argon2id$v=19$m=65536,t=2,p=4$c29tZXNhbHQ$GpZ3sK/oH9p7VIiV56G/64Zo/8GaUw434IimaPqxwCo",
			nil,
		},
		{
			"another password", // salt = anothersalt
			"$argon2id$v=19$m=65536,t=2,p=4$YW5vdGhlcnNhbHQ",
			"$argon2id$v=19$m=65536,t=2,p=4$YW5vdGhlcnNhbHQ$ZU9gSnQfqeEZG2Wu6Wq9pek2UAttI/N8NLCEecVBRZc",
			nil,
		},
		{
			"password", // salt = longsaltlongsaltlong
			"$argon2id$v=19$m=65536,t=2,p=1$bG9uZ3NhbHRsb25nc2FsdGxvbmc",
			"$argon2id$v=19$m=65536,t=2,p=1$bG9uZ3NhbHRsb25nc2FsdGxvbmc$y3Tz6SCUIw7occvkgsUYx0hwaePXLus7rxUzsOghhnE",
			nil,
		},
		{
			"ignore-hash-in-settings", // salt = longsaltlongsaltlong
			"$argon2id$v=19$m=65536,t=2,p=1$bG9uZ3NhbHRsb25nc2FsdGxvbmc$y3Tz6SCUIw7occvkgsUYx0hwaePXLus7rxUzsOghhnE",
			"$argon2id$v=19$m=65536,t=2,p=1$bG9uZ3NhbHRsb25nc2FsdGxvbmc$sToxuMqIBNNRYEPy2Gh690R7qa7mkhJ627ciTZdyQSA",
			nil,
		},
		{
			"password", // salt = longsaltlongsalt
			"$argon2id$v=19$m=65536,t=3,p=1$bG9uZ3NhbHRsb25nc2FsdA",
			"$argon2id$v=19$m=65536,t=3,p=1$bG9uZ3NhbHRsb25nc2FsdA$SHogC8dbNGlyrOIJTrZ4f0/r/ZmTglvCx4u5GUzw6EM",
			nil,
		},
	}

	for _, tc := range tcs {
		t.Run(tc.settings, func(t *testing.T) {
			result, err := crypt.Crypt(tc.password, tc.settings)
			require.Equal(t, tc.expectedErr, err)
			assert.True(t, strings.HasPrefix(result, tc.expectedResult), "expected prefix %q, got %q", tc.expectedResult, result)
		})
	}
}

func TestArgon2idSettings(t *testing.T) {
	tcs := []struct {
		m                      int
		t                      int
		p                      int
		expectedSettingsPrefix string
	}{
		{65536, 2, 4, "$argon2id$v=19$m=65536,t=2,p=4"},
	}

	for _, tc := range tcs {
		t.Run(fmt.Sprintf("m=%d,t=%d,p=%d", tc.m, tc.t, tc.p), func(t *testing.T) {
			settings, err := crypt.Argon2idSettings(tc.m, tc.t, tc.p)
			require.NoError(t, err)
			assert.True(t, strings.HasPrefix(settings, tc.expectedSettingsPrefix))
		})
	}
}
