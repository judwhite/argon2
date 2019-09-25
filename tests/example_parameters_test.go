package argon2_test

import (
	"fmt"
	"log"

	"github.com/judwhite/argon2"
)

func ExampleParameters() {
	hashedPassword, err := argon2.GenerateFromPassword([]byte("password"), argon2.Options{})
	if err != nil {
		log.Fatal(err)
	}

	p, err := argon2.Parameters(hashedPassword)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("function=%q, ver=%d, time=%d, mem=%d, threads=%d, saltlen=%d, keylen=%d",
		p.Function, p.Version, p.Time, p.Memory, p.Threads, p.SaltLen, p.KeyLen)
	// Output: function="argon2id", ver=19, time=5, mem=65536, threads=2, saltlen=16, keylen=32
}
