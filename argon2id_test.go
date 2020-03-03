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
	testFn := func(password, settings, expectResult string, expectErr error) (string, func(*testing.T)) {
		return settings, func(t *testing.T) {
			result, err := crypt.Crypt(password, settings)
			require.Equal(t, expectErr, err)
			assert.True(t, strings.HasPrefix(result, expectResult), "expected prefix %q, got %q", expectResult, result)
		}
	}

	t.Run(testFn("generate salt", "$argon2id$v=19$m=65536,t=2,p=4$",
		"$argon2id$v=19$m=65536,t=2$", nil))
	t.Run(testFn("password", "$argon2id$v=19$m=65536,t=2,p=4$c29tZXNhbHQ",
		"$argon2id$v=19$m=65536,t=2$c29tZXNhbHQ$GpZ3sK/oH9p7VIiV56G/64Zo/8GaUw434IimaPqxwCo", nil))
	t.Run(testFn("another password", "$argon2id$v=19$m=65536,t=2,p=4$YW5vdGhlcnNhbHQ",
		"$argon2id$v=19$m=65536,t=2$YW5vdGhlcnNhbHQ$ZU9gSnQfqeEZG2Wu6Wq9pek2UAttI/N8NLCEecVBRZc", nil))
	t.Run(testFn("password", "$argon2id$v=19$m=65536,t=2,p=1$bG9uZ3NhbHRsb25nc2FsdGxvbmc",
		"$argon2id$v=19$m=65536,t=2,p=1$bG9uZ3NhbHRsb25nc2FsdGxvbmc$y3Tz6SCUIw7occvkgsUYx0hwaePXLus7rxUzsOghhnE", nil))
	t.Run(testFn("ignore-hash-in-settings", "$argon2id$v=19$m=65536,t=2,p=1$bG9uZ3NhbHRsb25nc2FsdGxvbmc$y3Tz6SCUIw7occvkgsUYx0hwaePXLus7rxUzsOghhnE",
		"$argon2id$v=19$m=65536,t=2,p=1$bG9uZ3NhbHRsb25nc2FsdGxvbmc$sToxuMqIBNNRYEPy2Gh690R7qa7mkhJ627ciTZdyQSA", nil))
	t.Run(testFn("password", "$argon2id$v=19$m=65536,t=3,p=1$bG9uZ3NhbHRsb25nc2FsdA",
		"$argon2id$v=19$m=65536,t=3,p=1$bG9uZ3NhbHRsb25nc2FsdA$SHogC8dbNGlyrOIJTrZ4f0/r/ZmTglvCx4u5GUzw6EM", nil))
	t.Run(testFn("password", "$argon2id$v=19$m=65536,t=3,p=1,k=64$bG9uZ3NhbHRsb25nc2FsdA",
		"$argon2id$v=19$m=65536,t=3,p=1,k=64$bG9uZ3NhbHRsb25nc2FsdA$gaB/QbA34/AJkE/QbuEByjVhIF3sCvX+LHo8L3otGHhWh5q++cFMfidqGQd6qoGu3Qcm7LEPl8dQWMzyblYqYg", nil))
}

func TestArgon2idSettings(t *testing.T) {
	testFn := func(m, t, p, k int, expectSettingsPrefix string) (string, func(*testing.T)) {
		return fmt.Sprintf("m=%d,t=%d,p=%d,k=%d", m, t, p, k), func(tt *testing.T) {
			settings, err := crypt.Argon2idSettings(m, t, p, k)
			require.NoError(tt, err)
			assert.True(tt, strings.HasPrefix(settings, expectSettingsPrefix))
		}
	}

	t.Run(testFn(65536, 2, 4, 64, "$argon2id$v=19$m=65536,t=2,p=4,k=64"))
}
