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

package crypt

import (
	"bytes"
	"crypto/sha256"
	"strconv"
)

// SHA256Prefix defines the settings prefix for sha256 hashes.
const SHA256Prefix = "$5$"

const (
	sha256DefaultRounds = 5000
	sha256MinRounds     = 1000
	sha256MinSaltSize   = 1
	sha256MaxSaltSize   = 16
)

func init() {
	RegisterAlgorithm(SHA256Prefix, sha256Algorithm)
}

func sha256Algorithm(password, settings string) (string, error) {
	passwordBytes := []byte(password)
	_, parameter, salt, _, err := DecodeSettings(settings)
	if err != nil {
		return "", err
	}
	rounds := parameter.GetInt("rounds", sha256DefaultRounds)
	if rounds < sha256MinRounds {
		rounds = sha256MinRounds
	}
	saltBytes := []byte(salt)
	if len(saltBytes) > sha256MaxSaltSize {
		saltBytes = saltBytes[:sha256MaxSaltSize]
	}

	keyLen := len(passwordBytes)
	saltLen := len(saltBytes)
	h := sha256.New()

	// Compute sumB, step 4-8
	h.Write(passwordBytes)
	h.Write(saltBytes)
	h.Write(passwordBytes)
	sumB := h.Sum(nil)

	// Compute sumA, step 1-3, 9-12
	h.Reset()
	h.Write(passwordBytes)
	h.Write(saltBytes)
	h.Write(repeatByteSequence(sumB, keyLen))
	for i := keyLen; i > 0; i >>= 1 {
		if i%2 == 0 {
			h.Write(passwordBytes)
		} else {
			h.Write(sumB)
		}
	}
	sumA := h.Sum(nil)
	cleanSensitiveData(sumB)

	// Compute seqP, step 13-16
	h.Reset()
	for i := 0; i < keyLen; i++ {
		h.Write(passwordBytes)
	}
	seqP := repeatByteSequence(h.Sum(nil), keyLen)

	// Compute seqS, step 17-20
	h.Reset()
	for i := 0; i < 16+int(sumA[0]); i++ {
		h.Write(saltBytes)
	}
	seqS := repeatByteSequence(h.Sum(nil), saltLen)

	// step 21
	for i := 0; i < rounds; i++ {
		h.Reset()

		if i&1 != 0 {
			h.Write(seqP)
		} else {
			h.Write(sumA)
		}
		if i%3 != 0 {
			h.Write(seqS)
		}
		if i%7 != 0 {
			h.Write(seqP)
		}
		if i&1 != 0 {
			h.Write(sumA)
		} else {
			h.Write(seqP)
		}
		copy(sumA, h.Sum(nil))
	}
	cleanSensitiveData(seqP)
	cleanSensitiveData(seqS)

	// make output
	buf := bytes.Buffer{}
	buf.Grow(len([]byte(SHA256Prefix)) + len(roundsPrefix) + 9 + 1 + len(saltBytes) + 1 + 43)
	buf.Write([]byte(SHA256Prefix))
	if rounds != sha256DefaultRounds {
		buf.Write(roundsPrefix)
		buf.WriteString(strconv.Itoa(rounds))
		buf.WriteByte('$')
	}
	buf.Write(saltBytes)
	buf.WriteByte('$')
	buf.Write(Encode24BitBase64([]byte{
		sumA[20], sumA[10], sumA[0],
		sumA[11], sumA[1], sumA[21],
		sumA[2], sumA[22], sumA[12],
		sumA[23], sumA[13], sumA[3],
		sumA[14], sumA[4], sumA[24],
		sumA[5], sumA[25], sumA[15],
		sumA[26], sumA[16], sumA[6],
		sumA[17], sumA[7], sumA[27],
		sumA[8], sumA[28], sumA[18],
		sumA[29], sumA[19], sumA[9],
		sumA[30], sumA[31],
	}))
	return buf.String(), nil
}
