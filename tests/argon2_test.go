package argon2_test

import (
	"crypto/subtle"
	"encoding/hex"
	"testing"

	"github.com/judwhite/argon2"
)

func TestVectors(t *testing.T) {
	password, salt := []byte("password"), []byte("somesalt")
	for i, v := range testVectors {
		want, err := hex.DecodeString(v.hash)
		if err != nil {
			t.Fatalf("Test %d: failed to decode hash: %v", i, err)
		}
		hash, err := argon2.GenerateHashBytes(password, salt, v.time, v.memory, v.threads, uint32(len(want)))
		if err != nil {
			t.Fatalf("Test %d: failed to generate hash: %v", i, err)
		}
		if subtle.ConstantTimeCompare(hash, want) != 1 {
			t.Errorf("Test %d - got: %s want: %s", i, hex.EncodeToString(hash), hex.EncodeToString(want))
		}
	}
}

func TestGenerateFromPassword(t *testing.T) {
	password := []byte("password")
	str, err := argon2.GenerateFromPassword(password, argon2.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if err = argon2.CompareHashAndPassword(str, password); err != nil {
		t.Fatal(err)
	}
}

func TestGenerateFromPasswordMismatch(t *testing.T) {
	password := []byte("password")
	notPassword := []byte("notPassword")
	str, err := argon2.GenerateFromPassword(password, argon2.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if err = argon2.CompareHashAndPassword(str, notPassword); !argon2.IsPasswordMismatch(err) {
		t.Fatalf("hashes should not match")
	}
}

func BenchmarkGenerateFromPassword(b *testing.B) {
	password := []byte("password")
	var opts argon2.Options
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, err := argon2.GenerateFromPassword(password, opts); err != nil {
			b.Fatal(err)
		}
	}
}

func benchmarkArgon2(time, memory uint32, threads uint8, b *testing.B) {
	password := []byte("password")
	opts := argon2.Options{Time: time, Memory: memory, Threads: threads}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, err := argon2.GenerateFromPassword(password, opts); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkArgon2id(b *testing.B) {
	b.Run(" Time: 3, Memory: 32 MB, Threads: 1", func(b *testing.B) { benchmarkArgon2(3, 32*1024, 1, b) })
	b.Run(" Time: 4, Memory: 32 MB, Threads: 1", func(b *testing.B) { benchmarkArgon2(4, 32*1024, 1, b) })
	b.Run(" Time: 5, Memory: 32 MB, Threads: 1", func(b *testing.B) { benchmarkArgon2(5, 32*1024, 1, b) })
	b.Run(" Time: 3, Memory: 64 MB, Threads: 4", func(b *testing.B) { benchmarkArgon2(3, 64*1024, 4, b) })
	b.Run(" Time: 4, Memory: 64 MB, Threads: 4", func(b *testing.B) { benchmarkArgon2(4, 64*1024, 4, b) })
	b.Run(" Time: 5, Memory: 64 MB, Threads: 4", func(b *testing.B) { benchmarkArgon2(5, 64*1024, 4, b) })
}

var testVectors = []struct {
	time, memory uint32
	threads      uint8
	hash         string
}{
	{
		time: 1, memory: 64, threads: 1,
		hash: "655ad15eac652dc59f7170a7332bf49b8469be1fdb9c28bb",
	},
	{
		time: 2, memory: 64, threads: 1,
		hash: "068d62b26455936aa6ebe60060b0a65870dbfa3ddf8d41f7",
	},
	{
		time: 2, memory: 64, threads: 2,
		hash: "350ac37222f436ccb5c0972f1ebd3bf6b958bf2071841362",
	},
	{
		time: 3, memory: 256, threads: 2,
		hash: "4668d30ac4187e6878eedeacf0fd83c5a0a30db2cc16ef0b",
	},
	{
		time: 4, memory: 4096, threads: 4,
		hash: "145db9733a9f4ee43edf33c509be96b934d505a4efb33c5a",
	},
	{
		time: 4, memory: 1024, threads: 8,
		hash: "8dafa8e004f8ea96bf7c0f93eecf67a6047476143d15577f",
	},
	{
		time: 2, memory: 64, threads: 3,
		hash: "4a15b31aec7c2590b87d1f520be7d96f56658172deaa3079",
	},
	{
		time: 3, memory: 1024, threads: 6,
		hash: "1640b932f4b60e272f5d2207b9a9c626ffa1bd88d2349016",
	},
}
