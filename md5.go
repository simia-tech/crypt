package crypt

import (
	"bytes"
	"crypto/md5"
)

// MD5Prefix defines the settings prefix for md5 hashes.
const MD5Prefix = "$1$"

const (
	md5Rounds      = 1000
	md5MaxSaltSize = 8
)

func init() {
	RegisterAlgorithm(MD5Prefix, md5Algorithm)
}

func md5Algorithm(password, settings string) (string, error) {
	passwordBytes := []byte(password)
	_, _, salt, _, err := DecodeSettings(settings)
	if err != nil {
		return "", err
	}
	saltBytes := []byte(salt)
	if len(saltBytes) > md5MaxSaltSize {
		saltBytes = saltBytes[:md5MaxSaltSize]
	}

	keyLen := len(passwordBytes)
	h := md5.New()

	// Compute sumB
	h.Write(passwordBytes)
	h.Write(saltBytes)
	h.Write(passwordBytes)
	sumB := h.Sum(nil)

	// Compute sumA
	h.Reset()
	h.Write(passwordBytes)
	h.Write([]byte(MD5Prefix))
	h.Write(saltBytes)
	h.Write(repeatByteSequence(sumB, keyLen))
	// The original implementation now does something weird:
	//   For every 1 bit in the key, the first 0 is added to the buffer
	//   For every 0 bit, the first character of the key
	// This does not seem to be what was intended but we have to follow this to
	// be compatible.
	for i := keyLen; i > 0; i >>= 1 {
		if i%2 == 0 {
			h.Write(passwordBytes[0:1])
		} else {
			h.Write([]byte{0})
		}
	}
	sumA := h.Sum(nil)
	cleanSensitiveData(sumB)

	// In fear of password crackers here comes a quite long loop which just
	// processes the output of the previous round again.
	// We cannot ignore this here.
	for i := 0; i < md5Rounds; i++ {
		h.Reset()

		// Add key or last result.
		if i%2 != 0 {
			h.Write(passwordBytes)
		} else {
			h.Write(sumA)
		}
		// Add salt for numbers not divisible by 3.
		if i%3 != 0 {
			h.Write(saltBytes)
		}
		// Add key for numbers not divisible by 7.
		if i%7 != 0 {
			h.Write(passwordBytes)
		}
		// Add key or last result.
		if i&1 != 0 {
			h.Write(sumA)
		} else {
			h.Write(passwordBytes)
		}
		copy(sumA, h.Sum(nil))
	}

	buf := bytes.Buffer{}
	buf.Grow(len([]byte(MD5Prefix)) + len(saltBytes) + 1 + 22)
	buf.Write([]byte(MD5Prefix))
	buf.Write(saltBytes)
	buf.WriteByte('$')
	buf.Write(Encode24BitBase64([]byte{
		sumA[12], sumA[6], sumA[0],
		sumA[13], sumA[7], sumA[1],
		sumA[14], sumA[8], sumA[2],
		sumA[15], sumA[9], sumA[3],
		sumA[5], sumA[10], sumA[4],
		sumA[11],
	}))
	return buf.String(), nil
}
