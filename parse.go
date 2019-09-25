package argon2

import (
	"encoding/base64"
	"math"
	"strconv"
	"strings"

	a2 "golang.org/x/crypto/argon2"
)

type tokens struct {
	function     string
	version      int
	time, memory uint32
	threads      uint8
	salt         []byte
	hash         []byte
	keyLen       uint32
}

func parse(hashedPassword string) (tokens, error) {
	parts := strings.Split(hashedPassword, "$")

	if len(parts) != 6 {
		return tokens{}, &invalidFormat{}
	}
	if !strings.HasPrefix(hashedPassword, "$argon2id$") {
		return tokens{}, &invalidFormat{}
	}
	if !strings.HasPrefix(parts[2], "v=") {
		return tokens{}, &invalidFormat{}
	}
	mtp := strings.Split(parts[3], ",")
	if len(mtp) != 3 {
		return tokens{}, &invalidFormat{}
	}

	ver, err := strconv.Atoi(parts[2][2:])
	if err != nil {
		return tokens{}, &invalidFormat{}
	}
	if ver != a2.Version {
		return tokens{}, &invalidFormat{}
	}

	var m, t, p int
	for _, val := range mtp {
		if len(val) < 3 || val[1] != '=' {
			return tokens{}, &invalidFormat{}
		}
		x, err := strconv.Atoi(val[2:])
		if err != nil {
			return tokens{}, &invalidFormat{}
		}

		switch val[0] {
		case 'm':
			m = x
		case 't':
			t = x
		case 'p':
			p = x
		default:
			return tokens{}, &invalidFormat{}
		}
	}

	if m < 0 || t <= 0 || p <= 0 ||
		m > math.MaxUint32 ||
		t > math.MaxUint32 ||
		p > math.MaxUint8 {
		return tokens{}, &invalidFormat{}
	}

	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return tokens{}, &invalidFormat{}
	}

	hash, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil || len(hash) == 0 {
		return tokens{}, &invalidFormat{}
	}

	return tokens{
		function: parts[1],
		version:  ver,
		time:     uint32(t),
		memory:   uint32(m),
		threads:  uint8(p),
		salt:     salt,
		hash:     hash,
		keyLen:   uint32(len(hash)),
	}, nil
}
