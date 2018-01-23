package crypt

import (
	"strconv"
	"strings"
)

// Parameter defines a parameter map.
type Parameter map[string]string

// GetInt tries to return an int value from the parameter map and returns the provided
// defaultValue on failure.
func (p Parameter) GetInt(key string, defaultValue int) int {
	if p == nil {
		return defaultValue
	}
	text, found := p[key]
	if !found {
		return defaultValue
	}
	value, _ := strconv.Atoi(text)
	return value
}

// DecodeSettings decodes the provided settings string into it's parts.
func DecodeSettings(settings string) (string, Parameter, string, string, error) {
	parts := strings.Split(settings, "$")
	switch {
	case len(parts) == 3:
		return parts[1], nil, parts[2], "", nil
	case len(parts) >= 4:
		if strings.Contains(parts[2], "=") {
			pairs := strings.Split(parts[2], ",")
			p := Parameter{}
			for _, pair := range pairs {
				pairParts := strings.SplitN(pair, "=", 2)
				if len(pairParts) < 2 {
					continue
				}
				p[pairParts[0]] = pairParts[1]
			}
			if len(parts) >= 5 {
				return parts[1], p, parts[3], parts[4], nil
			}
			return parts[1], p, parts[3], "", nil
		}
		return parts[1], nil, parts[2], parts[3], nil
	}
	return "", nil, "", "", ErrInvalidSettings
}
