package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/simia-tech/crypt"
)

func main() {
	var (
		m = flag.Int("m", 65536, "memory cost in kb")
		t = flag.Int("t", 3, "time cost")
		p = flag.Int("p", 1, "number of threads")
		k = flag.Int("k", 32, "key size")
	)
	flag.Parse()

	password, salt := flag.Arg(0), flag.Arg(1)

	settings, err := crypt.Argon2iSettings(*m, *t, *p, *k, crypt.Base64Encoding.EncodeToString([]byte(salt)))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return
	}

	result, err := crypt.Crypt(password, settings)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return
	}

	fmt.Println(result)
}
