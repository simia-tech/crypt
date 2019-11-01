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

func TestSHA256(t *testing.T) {
	testFn := func(password, settings, expectResult string, expectErr error) (string, func(*testing.T)) {
		return settings, func(t *testing.T) {
			result, err := crypt.Crypt(password, settings)
			require.Equal(t, expectErr, err)
			assert.Equal(t, expectResult, result)
		}
	}

	t.Run(testFn("Hello world!", "$5$saltstring", "$5$saltstring$5B8vYYiY.CVt1RlTTf8KbXBH3hsxY/GNooZaBBGWEc5", nil))
	t.Run(testFn("Hello world!", "$5$rounds=10000$saltstringsaltstring", "$5$rounds=10000$saltstringsaltst$3xv.VbSHBb41AL9AvLeujZkZRBAwqFMz2.opqey6IcA", nil))
	t.Run(testFn("This is just a test", "$5$rounds=5000$toolongsaltstring", "$5$toolongsaltstrin$Un/5jzAHMgOGZ5.mWJpuVolil07guHPvOW8mGRcvxa5", nil))
	t.Run(testFn("a very much longer text to encrypt.  This one even stretches over morethan one line.", "$5$rounds=1400$anotherlongsaltstring", "$5$rounds=1400$anotherlongsalts$Rx.j8H.h8HjEDGomFU8bDkXm3XIUnzyxf12oP84Bnq1", nil))
	t.Run(testFn("we have a short salt string but not a short password", "$5$rounds=77777$short", "$5$rounds=77777$short$JiO1O3ZpDAxGJeaDIuqCoEFysAe1mZNJRs3pw0KQRd/", nil))
	t.Run(testFn("a short string", "$5$rounds=123456$asaltof16chars..", "$5$rounds=123456$asaltof16chars..$gP3VQ/6X7UUEW3HkBn2w1/Ptq2jxPyzV/cZKmF/wJvD", nil))
	t.Run(testFn("the minimum number is still observed", "$5$rounds=10$roundstoolow", "$5$rounds=1000$roundstoolow$yfvwcWrQ8l/K0DAWyuPMDNHpIVlTQebY9l/gL972bIC", nil))
}
