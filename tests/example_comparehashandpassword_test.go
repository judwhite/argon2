package argon2_test

import (
	"fmt"
	"log"

	"github.com/judwhite/argon2"
)

func ExampleCompareHashAndPassword() {
	const hash = "$argon2id$v=19$m=98304,t=5,p=2$AAECAwQFBgcICQoLDA0ODw$Ezmo1ZvImYjNdSrjbN33VEd5aUBeSmP3YZAojYw467I"
	password := []byte("some password")

	if err := argon2.CompareHashAndPassword(hash, password); err != nil {
		log.Fatal(err)
	}
	fmt.Println("passwords match")
	// Output: passwords match
}
