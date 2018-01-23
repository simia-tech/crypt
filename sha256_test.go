package crypt_test

import (
	"testing"

	"github.com/simia-tech/crypt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSHA256(t *testing.T) {
	tcs := []struct {
		password       string
		settings       string
		expectedResult string
		expectedErr    error
	}{
		{"Hello world!", "$5$saltstring", "$5$saltstring$5B8vYYiY.CVt1RlTTf8KbXBH3hsxY/GNooZaBBGWEc5", nil},
		{"Hello world!", "$5$rounds=10000$saltstringsaltstring", "$5$rounds=10000$saltstringsaltst$3xv.VbSHBb41AL9AvLeujZkZRBAwqFMz2.opqey6IcA", nil},
		{"This is just a test", "$5$rounds=5000$toolongsaltstring", "$5$toolongsaltstrin$Un/5jzAHMgOGZ5.mWJpuVolil07guHPvOW8mGRcvxa5", nil},
		{"a very much longer text to encrypt.  This one even stretches over morethan one line.", "$5$rounds=1400$anotherlongsaltstring", "$5$rounds=1400$anotherlongsalts$Rx.j8H.h8HjEDGomFU8bDkXm3XIUnzyxf12oP84Bnq1", nil},
		{"we have a short salt string but not a short password", "$5$rounds=77777$short", "$5$rounds=77777$short$JiO1O3ZpDAxGJeaDIuqCoEFysAe1mZNJRs3pw0KQRd/", nil},
		{"a short string", "$5$rounds=123456$asaltof16chars..", "$5$rounds=123456$asaltof16chars..$gP3VQ/6X7UUEW3HkBn2w1/Ptq2jxPyzV/cZKmF/wJvD", nil},
		{"the minimum number is still observed", "$5$rounds=10$roundstoolow", "$5$rounds=1000$roundstoolow$yfvwcWrQ8l/K0DAWyuPMDNHpIVlTQebY9l/gL972bIC", nil},
	}

	for _, tc := range tcs {
		t.Run(tc.settings, func(t *testing.T) {
			result, err := crypt.Crypt(tc.password, tc.settings)
			require.Equal(t, tc.expectedErr, err)
			assert.Equal(t, tc.expectedResult, result)
		})
	}
}
