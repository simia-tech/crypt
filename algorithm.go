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

// Algorithm defines a algorithm.
type Algorithm func(string, string) (string, error)

var algorithms = map[string]Algorithm{}

// RegisterAlgorithm registers an algorithm under the provided prefix.
func RegisterAlgorithm(prefix string, algorithm Algorithm) {
	algorithms[prefix] = algorithm
}
