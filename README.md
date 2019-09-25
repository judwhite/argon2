# argon2

[![GoDoc](https://godoc.org/github.com/judwhite/argon2?status.svg)](https://godoc.org/github.com/judwhite/argon2) [![MIT License](http://img.shields.io/:license-mit-blue.svg)](https://github.com/judwhite/argon2/blob/develop/LICENSE) [![Go Report Card](https://goreportcard.com/badge/github.com/judwhite/argon2)](https://goreportcard.com/report/github.com/judwhite/argon2)
[![CircleCI](https://circleci.com/gh/judwhite/argon2.svg?style=svg)](https://circleci.com/gh/judwhite/argon2)

Easy to use Argon2 password hashing for Go.

Provides an interface around [golang.org/x/crypto/argon2](https://godoc.org/golang.org/x/crypto/argon2) similar to the interface of the [golang.org/x/crypto/bcrypt](https://godoc.org/golang.org/x/crypto/bcrypt) package.

## Examples

### Create Password Hash

```go
package main

import (
    "fmt"
    "log"

    "github.com/judwhite/argon2"
)

func main() {
    // user input
    password := []byte("some password")

    str, err := argon2.GenerateFromPassword(password, argon2.Options{})
    if err != nil {
        log.Fatal(err)
    }
    fmt.Println(str) // store this output in a database
}
```

### Validate Password Hash

```go
package main

import (
    "fmt"
    "log"

    "github.com/judwhite/argon2"
)

func main() {
    // retrieved from a database
    const hash = "$argon2id$v=19$m=98304,t=5,p=2$AAECAwQFBgcICQoLDA0ODw$Ezmo1ZvImYjNdSrjbN33VEd5aUBeSmP3YZAojYw467I"

    // user input
    password := []byte("some password")

    // validate passwords match
    if err := argon2.CompareHashAndPassword(hash, password); err != nil {
        log.Fatal(err)
    }
    fmt.Println("passwords match")
}
```

## Similar Projects

- https://godoc.org/golang.org/x/crypto/argon2
- https://github.com/p-h-c/phc-winner-argon2
- https://github.com/alexedwards/argon2id

## License

argon2 is under the MIT license. See the [LICENSE](https://github.com/judwhite/argon2/blob/develop/LICENSE) file for details.
