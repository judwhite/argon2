package argon2_test

import (
	"fmt"
	"log"

	"github.com/judwhite/argon2"
)

func ExampleGenerateHashBytes() {
	const (
		time      = 5
		memory    = 64 * 1024
		threads   = 2
		keyLength = 32
	)

	// WARNING: 'salt' is initialized here only to produce consistent output; see commented out code below
	salt := []byte("DO_NOT_USE")

	// Use "crypto/rand" to generate a salt.
	// salt := make([]byte, 16)
	// if _, err := rand.Read(salt); err != nil {
	//     log.Fatal(err)
	// }

	hash, err := argon2.GenerateHashBytes([]byte("some password"), salt, time, memory, threads, keyLength)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("%x\n", hash)
	// Output: 71a06e974cda6ac2bdc6d5f27bbb4085bf3dc8726c103f193779fbf4fbff27fd
}
