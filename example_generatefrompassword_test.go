package argon2_test

import (
	"fmt"
	"log"

	"github.com/judwhite/argon2"
)

func ExampleGenerateFromPassword() {
	str, err := argon2.GenerateFromPassword([]byte("some password"), argon2.Options{})
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(str)
}
