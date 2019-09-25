// Package argon2 provides an interface around golang.org/x/crypto/argon2 similar to the interface of the bcrypt package.
//
// This package is intended for password hashing, particularly for user databases. GenerateFromPassword returns a
// formatted string suitable for database storage. This value can be used by CompareHashAndPassword to check if
// a plaintext password matches the hash.
//
// For more information about Argon2 visit https://github.com/p-h-c/phc-winner-argon2 and
// https://godoc.org/golang.org/x/crypto/argon2.
package argon2

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"fmt"

	a2 "golang.org/x/crypto/argon2"
)

const (
	defaultSaltLen = 16
	defaultKeyLen  = 32
)

// GenerateFromPassword returns the Argon2 hashed password using the provided options. The options are similar to how
// Cost works in bcrypt and allow you to tune the memory and CPU usage for your environment. If you pass an empty
// Options struct defaults will be chosen, though you should test these parameters under your expected load. It's safe
// to reuse a single Options instance from multiple goroutines, provided it's not modified while calling the function.
//
// Use CompareHashAndPassword to compare the returned hashed password with its plaintext version.
//
// A 16-byte salt is created using crypto/rand. The salt is not provided as a parameter or in the options to discourage
// reusing salt values. The output of the hash, also referred to as the key length, is set to the recommended 32 bytes.
//
// The hash is returned formatted, as in the reference implementation:
// "$argon2id$v=19$m=<num>,t=<num>,p=<num>$<salt-base64>$<hash-base64>".
func GenerateFromPassword(password []byte, opts Options) (string, error) {
	if len(password) == 0 {
		return "", fmt.Errorf("password length cannot be 0")
	}

	salt := make([]byte, defaultSaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}

	opts.setDefaults()

	hash, err := GenerateHashBytes(password, salt, opts.Time, opts.Memory, opts.Threads, defaultKeyLen)
	if err != nil {
		return "", err
	}

	str := fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		a2.Version, opts.Memory, opts.Time, opts.Threads,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(hash),
	)

	return str, nil
}

// CompareHashAndPassword compares an Argon2 hashed password, as returned from GenerateFromPassword, with a plaintext
// password. Returns nil if the passwords match, otherwise returns an error.
func CompareHashAndPassword(hashedPassword string, password []byte) error {
	p, err := parse(hashedPassword)
	if err != nil {
		return err
	}

	compareHash, err := GenerateHashBytes(password, p.salt, p.time, p.memory, p.threads, p.keyLen)
	if err != nil {
		return err
	}

	if subtle.ConstantTimeCompare(p.hash, compareHash) != 1 {
		return &passwordMismatch{}
	}

	return nil
}

// GenerateHashBytes calls the underlying Argon2id implementation in crypto/argon2. It returns only the hash without
// option information or formatting.
func GenerateHashBytes(password, salt []byte, time, memory uint32, threads uint8, keyLen uint32) ([]byte, error) {
	if time == 0 {
		return nil, fmt.Errorf("time cannot be 0")
	}
	if threads == 0 {
		return nil, fmt.Errorf("threads cannot be 0")
	}
	if keyLen == 0 {
		return nil, fmt.Errorf("keyLen cannot be 0")
	}

	return a2.IDKey(password, salt, time, memory, threads, keyLen), nil
}

// Parameters returns the hashing parameters used to create the given hashed password. When, in the future, the hashing
// cost of a password system needs to be changed in order to adjust for greater computational power, this function
// allows one to establish which passwords need to be updated.
func Parameters(hashedPassword string) (HashParameters, error) {
	t, err := parse(hashedPassword)
	if err != nil {
		return HashParameters{}, err
	}

	return HashParameters{
		Function: t.function,
		Version:  t.version,
		Time:     t.time,
		Memory:   t.memory,
		Threads:  t.threads,
		SaltLen:  uint32(len(t.salt)),
		KeyLen:   t.keyLen,
	}, nil
}
