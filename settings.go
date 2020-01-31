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
	"regexp"
	"strconv"
	"strings"
)

var (
	roundsPrefix = []byte("rounds=")
	costRegexp   = regexp.MustCompile(`^[0-9]{2}$`)
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

// Settings removes the hash from the provided settings and returns the result.
func Settings(settings string) (string, error) {
	parts := strings.Split(settings, "$")
	keep := 3
	if len(parts) > 3 {
		if s := parts[2]; strings.Contains(s, "=") || costRegexp.MatchString(s) {
			keep++
		}
	}
	if len(parts) > 4 {
		if s := parts[3]; strings.Contains(s, "=") || costRegexp.MatchString(s) {
			keep++
		}
	}
	return strings.Join(parts[:keep], "$"), nil
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
			} else if costRegexp.MatchString(part) {
				if parameter == nil {
					parameter = Parameter{}
				}
				parameter["cost"] = strings.Trim(part, "0")
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
