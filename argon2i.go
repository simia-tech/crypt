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
