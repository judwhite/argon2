package argon2

type invalidFormat struct{
	message string
}

func (e *invalidFormat) Error() string {
	if e.message != "" {
		return e.message
	}
	return "invalid format"
}

type passwordMismatch struct{}

func (e *passwordMismatch) Error() string {
	return "password mismatch"
}

// IsPasswordMismatch reports whether an error returned by CompareHashAndPassword is the result of a password
// mismatch, opposed to another type of error such as an invalid format.
func IsPasswordMismatch(err error) bool {
	_, ok := err.(*passwordMismatch)
	return ok
}
