// Package argon2 provides an interface around golang.org/x/crypto/argon2 similar to the interface of the bcrypt package.
//
// This package is intended for password hashing, particularly for user databases. GenerateFromPassword returns a
// formatted string suitable for database storage. This value can be used by CompareHashAndPassword to check if
// a plaintext password matches the hash.
//
// For more information about Argon2 visit https://github.com/p-h-c/phc-winner-argon2 and
// https://godoc.org/golang.org/x/crypto/argon2.
package argon2
