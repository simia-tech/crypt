// Copied from https://github.com/golang/crypto/tree/master/bcrypt

package bcrypt

import (
	"encoding/base64"
)

const alphabet = "./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"

var bcEncoding = base64.NewEncoding(alphabet).WithPadding(base64.NoPadding)

// Base64Encode returns the base64 encoded version of the provided string using an alternative alphabet.
func Base64Encode(src []byte) []byte {
	dst := make([]byte, bcEncoding.EncodedLen(len(src)))
	bcEncoding.Encode(dst, src)
	return dst
}

// Base64Decode returns the decoded version of the provided base64 string.
func Base64Decode(src []byte) ([]byte, error) {
	dst := make([]byte, bcEncoding.DecodedLen(len(src)))
	_, err := bcEncoding.Decode(dst, src)
	if err != nil {
		return nil, err
	}
	return dst, nil
}
