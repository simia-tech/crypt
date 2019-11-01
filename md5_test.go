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

func TestMD5(t *testing.T) {
	testFn := func(password, settings, expectResult string, expectErr error) (string, func(*testing.T)) {
		return settings, func(t *testing.T) {
			result, err := crypt.Crypt(password, settings)
			require.Equal(t, expectErr, err)
			assert.Equal(t, expectResult, result)
		}
	}

	t.Run(testFn("abcdefghijk", "$1$$", "$1$$pL/BYSxMXs.jVuSV1lynn1", nil))
	t.Run(testFn("abcdfgh", "$1$an overlong salt$", "$1$an overl$ZYftmJDIw8sG5s4gG6r.70", nil))
	t.Run(testFn("Lorem ipsum dolor sit amet", "$1$12345678$", "$1$12345678$Suzx8CrBlkNJwVHHHv5tZ.", nil))
	t.Run(testFn("password", "$1$deadbeef$", "$1$deadbeef$Q7g0UO4hRC0mgQUQ/qkjZ0", nil))
	t.Run(testFn("1234567", "$1$holy-moly-batman$", "$1$holy-mol$WKomB0dWknSxdW/e8WYHG0", nil))
	t.Run(testFn("A really long password. Longer than a password has any right to be. Hey bub, don't mess with this password.", "$1$asdfjkl;$", "$1$asdfjkl;$DUqPhKwbK4smV0aEMyDdx/", nil))
}
