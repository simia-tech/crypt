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
	"crypto/rand"
	"fmt"
	"strconv"
	"strings"

	"golang.org/x/crypto/argon2"
)

// Argon2iPrefix defines the settings prefix for argon2i hashes.
const Argon2iPrefix = "$argon2i$"

func init() {
	RegisterAlgorithm(Argon2iPrefix, argon2iAlgorithm)
}

const (
	argon2iDefaultMemory   = 32 * 1024
	argon2iDefaultTime     = 4
	argon2iDefaultThreads  = 4
	argon2iDefaultKeySize  = 32
	argon2iDefaultSaltSize = 16
)

// Argon2iSettings returns argon2i settings with the provided parameter.
func Argon2iSettings(m, t, p, k int, salts ...string) (string, error) {
	settings := fmt.Sprintf("%sv=19$m=%d,t=%d,p=%d,k=%d", Argon2iPrefix, m, t, p, k)
	salt := strings.Join(salts, "")
	if salt == "" {
		b := make([]byte, argon2iDefaultSaltSize)
		rand.Read(b)
		salt = Base64Encoding.EncodeToString(b)
	}
	return settings + "$" + salt, nil
}

func argon2iAlgorithm(password, settings string) (string, error) {
	passwordBytes := []byte(password)
	_, parameter, salt, _, err := DecodeSettings(settings)
	if err != nil {
		return "", err
	}
	saltBytes := []byte{}
	if salt == "" {
		saltBytes = make([]byte, argon2iDefaultSaltSize)
		rand.Read(saltBytes)
	} else {
		saltBytes, err = Base64Encoding.DecodeString(salt)
		if err != nil {
			return "", fmt.Errorf("base64 decode [%s]: %v", salt, err)
		}
	}
	memory := parameter.GetInt("m", argon2iDefaultMemory)
	time := parameter.GetInt("t", argon2iDefaultTime)
	threads := parameter.GetInt("p", argon2iDefaultThreads)
	keySize := parameter.GetInt("k", argon2iDefaultKeySize)

	hash := argon2.Key(passwordBytes, saltBytes, uint32(time), uint32(memory), uint8(threads), uint32(keySize))

	p := []string{}

	p = append(p, "m="+strconv.Itoa(memory))
	p = append(p, "t="+strconv.Itoa(time))
	p = append(p, "p="+strconv.Itoa(threads))

	if keySize != argon2iDefaultKeySize {
		p = append(p, "k="+strconv.Itoa(keySize))
	}

	buf := bytes.Buffer{}
	buf.Write([]byte(Argon2iPrefix))
	buf.WriteString("v=19$")
	if len(p) > 0 {
		buf.WriteString(strings.Join(p, ","))
		buf.WriteString("$")
	}
	buf.WriteString(Base64Encoding.EncodeToString(saltBytes))
	buf.WriteString("$")
	buf.WriteString(Base64Encoding.EncodeToString(hash))
	return buf.String(), nil
}
