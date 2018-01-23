package crypt

import (
	"strings"
)

// DecodeSettings decodes the provided settings string into it's parts.
func DecodeSettings(settings string) (string, string, string, error) {
	parts := strings.Split(settings, "$")
	switch {
	case len(parts) == 3:
		return parts[1], parts[2], "", nil
	case len(parts) >= 4:
		return parts[1], parts[2], parts[3], nil
	}
	return "", "", "", ErrInvalidSettings
}
