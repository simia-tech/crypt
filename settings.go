package crypt

import (
	"strconv"
	"strings"
)

var roundsPrefix = []byte("rounds=")

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
func DecodeSettings(settings string) (code string, parameter Parameter, salt string, hash string, err error) {
	step := 0
	for _, part := range strings.Split(settings, "$") {
		switch step {
		case 0, 1:
			code = part
			step++
		case 2:
			if strings.Contains(part, "=") {
				if parameter == nil {
					parameter = Parameter{}
				}
				parameter = decodeParameters(parameter, part)
			} else {
				salt = part
				step++
			}
		case 3:
			hash = part
			step++
		}
	}
	return
}

func decodeParameters(p Parameter, text string) Parameter {
	pairs := strings.Split(text, ",")
	for _, pair := range pairs {
		parts := strings.SplitN(pair, "=", 2)
		if len(parts) < 2 {
			continue
		}
		p[parts[0]] = parts[1]
	}
	return p
}
