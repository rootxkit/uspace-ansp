package manned

import (
	"crypto/rand"
	"encoding/binary"
	"time"
)

// crockford is the ULID alphabet (Crockford base32: no I, L, O, U).
const crockford = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

// NewULID is a ULID for msg_id (04 §2, the envelope's ulid pattern
// ^[0-7][0-9A-HJKMNP-TV-Z]{25}$): 48 bits of milliseconds since the Unix
// epoch, then 80 random bits, as 26 Crockford base32 characters, most
// significant first. A time before the epoch is 0 and one past the 48-bit
// range is the maximum, so the first character is always 0-7.
func NewULID(t time.Time) string {
	var entropy [10]byte
	_, _ = rand.Read(entropy[:]) // crypto/rand.Read never fails (Go 1.24+)
	return ULIDWithEntropy(t, entropy)
}

// ULIDWithEntropy is the ULID of t with the given 80 random bits
// (deterministic: generators and tests).
func ULIDWithEntropy(t time.Time, entropy [10]byte) string {
	ms := t.UnixMilli()
	switch {
	case ms < 0:
		ms = 0
	case ms > 1<<48-1:
		ms = 1<<48 - 1
	}
	// 128 bits: hi = 48-bit time and the first 16 random bits, lo = the
	// remaining 64 random bits.
	hi := uint64(ms)<<16 | uint64(binary.BigEndian.Uint16(entropy[0:2]))
	lo := binary.BigEndian.Uint64(entropy[2:10])
	var out [26]byte
	for i := 25; i >= 0; i-- {
		out[i] = crockford[lo&31]
		lo = lo>>5 | hi<<59
		hi >>= 5
	}
	return string(out[:])
}
