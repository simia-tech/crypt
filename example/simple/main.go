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

package main

import (
	"fmt"
	"log"

	"github.com/simia-tech/crypt"
)

func main() {
	password := "password"
	settings := "$argon2i$v=19$m=65536,t=2,p=4$c2FsdHNhbHQ" // salt = "saltsalt"

	encoded, err := crypt.Crypt(password, settings)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(encoded)
	// Output: $argon2i$v=19$m=65536,t=2$c2FsdHNhbHQ$YPZdL78ZgqtxD1bLxAjRySEFfYb3Y1BOQQWFW6sT0Vo
}
