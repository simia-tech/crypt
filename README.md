
# Crypt

[![Build Status](https://travis-ci.org/simia-tech/crypt.svg?branch=master)](https://travis-ci.org/simia-tech/crypt) [![Go Report Card](https://goreportcard.com/badge/github.com/simia-tech/crypt)](https://goreportcard.com/report/github.com/simia-tech/crypt)  [![Documentation](https://godoc.org/github.com/simia-tech/crypt?status.svg)](http://godoc.org/github.com/simia-tech/crypt)

Crypt implementation in pure Go

# Example

```go
func main() {
	password := "password"
	settings := "$argon2id$v=19$m=65536,t=2,p=4$c2FsdHNhbHQ" // salt = "saltsalt"

	encoded, err := crypt.Crypt(password, settings)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(encoded)
	// Output: $argon2id$v=19$m=65536,t=2,p=4$c2FsdHNhbHQ$mxUf7CB5gEwtDSiHfZCvxj17E8XeTFh2fpti1ioD3SA
}
```

# Algorithm

Currently, the following algorithms are supported:

|  Code    | Name     | Example                                                                                              |
|----------|----------|------------------------------------------------------------------------------------------------------|
|        1 | MD5      | $1$deadbeef$Q7g0UO4hRC0mgQUQ/qkjZ0                                                                   |
|        5 | SHA256   | $5$saltstring$5B8vYYiY.CVt1RlTTf8KbXBH3hsxY/GNooZaBBGWEc5                                            |
|        6 | SHA512   | $6$saltstring$svn8UoSVapNtMuq1ukKS4tPQd8iKwSMHWjl/O817G3uBnIFNjnQJuesI68u4OTLiBFdcbYEdFCoEOfaS35inz1 |
|       2a | bcrypt   | $2a$05$/OK.fbVrR/bpIqNJ5ianF.Sa7shbm4.OzKpvFnX1pQLmQW96oUlCq                                         |
|  argon2i | Argon2i  | $argon2i$v=19$m=65536,t=2$c29tZXNhbHQ$IMit9qkFULCMA/ViizL57cnTLOa5DiVM9eMwpAvPwr4                    |
| argon2id | Argon2id | $argon2id$v=19$m=65536,t=2,p=4$c29tZXNhbHQ$GpZ3sK/oH9p7VIiV56G/64Zo/8GaUw434IimaPqxwCo               |

It's recommended that you used `argon2id` for crypting passwords.

# Links

This implementation is inspired by [crypt](https://github.com/GehirnInc/crypt).

# License

The code is licensed under [Apache 2.0](http://www.apache.org/licenses/LICENSE-2.0)
