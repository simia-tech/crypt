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
	argon2iDefaultMemory  = 32 * 1024
	argon2iDefaultTime    = 4
	argon2iDefaultThreads = 4
	argon2iKeySize        = 32
	argon2iMaxSaltSize    = 0xFFFFFFFF
)

func argon2iAlgorithm(password, settings string) (string, error) {
	passwordBytes := []byte(password)
	_, parameter, salt, _, err := DecodeSettings(settings)
	if err != nil {
		return "", err
	}
	saltBytes, err := Base64Encoding.DecodeString(salt)
	if err != nil {
		return "", fmt.Errorf("base64 decode [%s]: %v", salt, err)
	}
	if len(saltBytes) > argon2iMaxSaltSize {
		saltBytes = saltBytes[:argon2iMaxSaltSize]
	}
	memory := parameter.GetInt("m", argon2iDefaultMemory)
	time := parameter.GetInt("t", argon2iDefaultTime)
	threads := parameter.GetInt("p", argon2iDefaultThreads)

	hash := argon2.Key(passwordBytes, saltBytes, uint32(time), uint32(memory), uint8(threads), argon2iKeySize)

	p := []string{}
	if memory != argon2iDefaultMemory {
		p = append(p, "m="+strconv.Itoa(memory))
	}
	if time != argon2iDefaultTime {
		p = append(p, "t="+strconv.Itoa(time))
	}
	if threads != argon2iDefaultThreads {
		p = append(p, "p="+strconv.Itoa(threads))
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
