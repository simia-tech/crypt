package crypt

import (
	"fmt"
	"strings"
)

// Crypt hashes the provided password using the provided salt.
func Crypt(password, settings string) (string, error) {
	for prefix, algorithm := range algorithms {
		if strings.HasPrefix(settings, prefix) {
			return algorithm(password, settings)
		}
	}
	return "", fmt.Errorf("no registered algorithm for settings [%s]", settings)
}
