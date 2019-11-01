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

func TestBCrypt(t *testing.T) {
	testFn := func(password, settings, expectResult string, expectErr error) (string, func(*testing.T)) {
		return settings, func(t *testing.T) {
			result, err := crypt.Crypt(password, settings)
			require.Equal(t, expectErr, err)
			assert.Equal(t, expectResult, result)
		}
	}

	t.Run(testFn("U*U", "$2a$05$CCCCCCCCCCCCCCCCCCCCC.", "$2a$05$CCCCCCCCCCCCCCCCCCCCC.E5YPO9kmyuRGyh0XouQYb4YMJKvyOeW", nil))
	t.Run(testFn("U*U*", "$2a$05$CCCCCCCCCCCCCCCCCCCCC.", "$2a$05$CCCCCCCCCCCCCCCCCCCCC.VGOzA784oUp/Z0DY336zx7pLYAy0lwK", nil))
	t.Run(testFn("U*U*U", "$2a$05$XXXXXXXXXXXXXXXXXXXXXO", "$2a$05$XXXXXXXXXXXXXXXXXXXXXOAcXxm9kjPGEMsLznoKqmqw7tc8WCx4a", nil))
	t.Run(testFn("0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789chars after 72 are ignored", "$2a$05$abcdefghijklmnopqrstuu", "$2a$05$abcdefghijklmnopqrstuu5s2v8.iXieOjg/.AySBTTZIIVFJeBui", nil))
	t.Run(testFn("\xa3", "$2a$05$/OK.fbVrR/bpIqNJ5ianF.", "$2a$05$/OK.fbVrR/bpIqNJ5ianF.Sa7shbm4.OzKpvFnX1pQLmQW96oUlCq", nil))
	t.Run(testFn("", "$2a$05$CCCCCCCCCCCCCCCCCCCCC.", "$2a$05$CCCCCCCCCCCCCCCCCCCCC.7uG0VCzI2bS7j6ymqJi9CdcdxiRTWNy", nil))
}

func TestBCryptSettings(t *testing.T) {
	testFn := func(cost int, expectSettingsPrefix string) (string, func(*testing.T)) {
		return fmt.Sprintf("cost=%d", cost), func(t *testing.T) {
			settings, err := crypt.BCryptSettings(cost)
			require.NoError(t, err)
			assert.True(t, strings.HasPrefix(settings, expectSettingsPrefix))
		}
	}

	t.Run(testFn(5, "$2a$05"))
	t.Run(testFn(10, "$2a$10"))
	t.Run(testFn(15, "$2a$15"))
}
