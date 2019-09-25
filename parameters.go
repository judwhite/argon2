package argon2

// HashParameters contains parameters used to create an Argon2 hash. It's returned by the Parameters function.
type HashParameters struct {
	// Function is the name of the hash function used, such as "argon2id".
	Function string
	// Version is the version of Argon2 used to create the hash.
	Version int
	// Time is the number of iterations, affecting the time cost.
	Time uint32
	// Memory is the size of the memory used in KiB, affecting the memory cost.
	Memory uint32
	// Threads is the number of threads, affecting the degree of parallelism.
	Threads uint8
	// SaltLen is the length of the salt value.
	SaltLen uint32
	// KeyLen is the length of the output hash value.
	KeyLen uint32
}

// Parameters returns the hashing parameters used to create the given hashed password. When, in the future, the hashing
// cost of a password system needs to be increased in order to adjust for greater computational power, this function
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
