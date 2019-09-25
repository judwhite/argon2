package argon2

const (
	defaultTime    = 5
	defaultMemory  = 64 * 1024
	defaultThreads = 2
)

// Options for affecting the computational cost.
type Options struct {
	// Time is the number of iterations, affecting the time cost.
	// If unset, the default value is 5.
	Time uint32
	// Memory is the size of the memory used in KiB, affecting the memory cost.
	// If unset, the default value is 65536 (64 MiB).
	Memory uint32
	// Threads is the number of threads, affecting the degree of parallelism.
	// If unset the default value is 2.
	Threads uint8
}

func (opts *Options) setDefaults() {
	if opts.Time == 0 {
		opts.Time = defaultTime
	}
	if opts.Memory == 0 {
		opts.Memory = defaultMemory
	}
	if opts.Threads == 0 {
		opts.Threads = defaultThreads
	}
}
