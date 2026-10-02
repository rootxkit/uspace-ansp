package restriction

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"strings"
	"time"
)

// IdentifierPrefix starts every restriction identifier (D4, M10): the
// ED-318 identifier is at most 7 characters, so DAR plus 4 base-36
// characters, without the hyphen of 03 section 6.
const IdentifierPrefix = "DAR"

// IdentifierSpace is how many identifiers DAR plus 4 base-36 characters
// can name (36^4). The database sequence runs 0..IdentifierSpace-1 and
// refuses to cycle: an identifier names one restriction for ever (the
// CISP refuses a reused one).
const IdentifierSpace = 36 * 36 * 36 * 36

// identifierStride permutes the sequence over the space: coprime with
// 36^4 = 2^8 * 3^4 (odd, not a multiple of 3), so n -> n*stride+offset
// mod 36^4 is a bijection, and consecutive restrictions do not get
// consecutive identifiers.
const identifierStride = 1_000_003

const base36 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"

// Identifier is the identifier of sequence value seq under the
// database's offset (restriction_identifier_key): distinct for every
// seq in [0, IdentifierSpace) and the same offset. A value outside the
// space is refused, never wrapped.
func Identifier(seq, offset int64) (string, error) {
	if seq < 0 || seq >= IdentifierSpace {
		return "", fmt.Errorf("restriction identifier sequence %d is outside [0, %d): the DAR identifier space is exhausted", seq, IdentifierSpace)
	}
	if offset < 0 || offset >= IdentifierSpace {
		return "", fmt.Errorf("restriction identifier offset %d is outside [0, %d)", offset, IdentifierSpace)
	}
	n := (seq*identifierStride + offset) % IdentifierSpace
	var b [4]byte
	for i := 3; i >= 0; i-- {
		b[i] = base36[n%36]
		n /= 36
	}
	return IdentifierPrefix + string(b[:]), nil
}

// ValidIdentifier reports whether id is DAR plus 4 base-36 characters.
func ValidIdentifier(id string) bool {
	rest, ok := strings.CutPrefix(id, IdentifierPrefix)
	if !ok || len(rest) != 4 {
		return false
	}
	for i := 0; i < len(rest); i++ {
		if !strings.ContainsRune(base36, rune(rest[i])) {
			return false
		}
	}
	return true
}

// crockford is the ULID alphabet (Crockford base32: no I, L, O, U).
const crockford = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

// NewULID is a ULID (04 section 2): 48 bits of milliseconds since the
// epoch, then 80 random bits, as 26 Crockford base32 characters.
func NewULID(t time.Time) string {
	var entropy [10]byte
	_, _ = rand.Read(entropy[:]) // crypto/rand.Read never fails (Go 1.24+)
	ms := t.UnixMilli()
	switch {
	case ms < 0:
		ms = 0
	case ms > 1<<48-1:
		ms = 1<<48 - 1
	}
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
