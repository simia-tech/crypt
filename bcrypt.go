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
	"crypto/rand"
	"fmt"
	"strings"

	"github.com/simia-tech/crypt/internal/bcrypt"
)

// BCryptPrefix defines the settings prefix for bcrypt hashes.
const BCryptPrefix = "$2a$"

func init() {
	RegisterAlgorithm(BCryptPrefix, bcryptAlgorithm)
}

const (
	bcryptSaltSize        = 16
	bcryptEncodedSaltSize = 22
)

// BCryptSettings returns bcrypt settings with the provided parameter.
func BCryptSettings(cost int, salts ...string) (string, error) {
	settings := fmt.Sprintf("%s%02d", BCryptPrefix, cost)
	salt := strings.Join(salts, "")
	if salt == "" {
		b := make([]byte, bcryptSaltSize)
		rand.Read(b)
		salt = string(bcrypt.Base64Encode(b))
	}
	if l := len(salt); l != bcryptEncodedSaltSize {
		return "", fmt.Errorf("expected a salt length of %d, got %d", bcryptEncodedSaltSize, l)
	}
	return settings + "$" + salt, nil
}

func bcryptAlgorithm(password, settings string) (string, error) {
	for len(settings) < 59 {
		settings += "A"
	}

	cost, err := bcrypt.Cost([]byte(settings))
	if err != nil {
		return "", fmt.Errorf("cost: %v", err)
	}

	salt, err := bcrypt.Salt([]byte(settings))
	if err != nil {
		return "", fmt.Errorf("salt: %v", err)
	}

	hash, err := bcrypt.GenerateFromPasswordAndSalt([]byte(password), cost, salt)
	if err != nil {
		return "", fmt.Errorf("hash: %v", err)
	}

	return string(hash), nil
}
