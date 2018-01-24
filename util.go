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

const (
	cleanBytesLen = 64
)

var (
	cleanBytes = make([]byte, cleanBytesLen)
)

func cleanSensitiveData(b []byte) {
	l := len(b)

	for ; l > cleanBytesLen; l -= cleanBytesLen {
		copy(b[l-cleanBytesLen:l], cleanBytes)
	}

	if l > 0 {
		copy(b[0:l], cleanBytes[0:l])
	}
}

func repeatByteSequence(input []byte, length int) []byte {
	var (
		sequence = make([]byte, length)
		unit     = len(input)
	)

	j := length / unit * unit
	for i := 0; i < j; i += unit {
		copy(sequence[i:length], input)
	}
	if j < length {
		copy(sequence[j:length], input[0:length-j])
	}

	return sequence
}
