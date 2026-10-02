package auth

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"strings"
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/hotp"
	"github.com/pquerna/otp/totp"
	"github.com/rootxkit/uspace-core/core"
)

// TOTP parameters (RFC 6238 defaults every authenticator app reads):
// SHA-1, 6 digits, 30 s period, a 160-bit secret, one step of skew on
// each side.
const (
	TOTPPeriod     = 30 * time.Second
	TOTPSkewSteps  = 1
	TOTPSecretSize = 20
	// TOTPIssuer is the issuer label authenticator apps show.
	TOTPIssuer = "uspace-ansp"
)

var base32NoPad = base32.StdEncoding.WithPadding(base32.NoPadding)

// NewTOTPSecret makes an enrolment: the base32 secret and the otpauth
// URI authenticator apps scan. Generation is pquerna/otp's.
func NewTOTPSecret(account string) (secret, uri string, err error) {
	k, err := totp.Generate(totp.GenerateOpts{Issuer: TOTPIssuer, AccountName: account, SecretSize: TOTPSecretSize})
	if err != nil {
		return "", "", err
	}
	return k.Secret(), k.URL(), nil
}

// TOTPURI renders the otpauth URI of an existing secret (a pending
// enrolment shown again).
func TOTPURI(account, secret string) (string, error) {
	raw, err := base32NoPad.DecodeString(strings.ToUpper(secret))
	if err != nil {
		return "", err
	}
	k, err := totp.Generate(totp.GenerateOpts{Issuer: TOTPIssuer, AccountName: account, Secret: raw})
	if err != nil {
		return "", err
	}
	return k.URL(), nil
}

// VerifyTOTP checks code against secret at now, within one step of skew,
// and returns the time step it matched. A step at or before lastStep is
// refused: each code is accepted once (RFC 6238 section 5.2). The
// comparison is pquerna/otp's constant-time one.
func VerifyTOTP(secret, code string, now time.Time, lastStep int64) (int64, bool) {
	if len(code) != 6 {
		return 0, false
	}
	for _, c := range code {
		if c < '0' || c > '9' {
			return 0, false
		}
	}
	step := now.Unix() / int64(TOTPPeriod/time.Second)
	for d := int64(-TOTPSkewSteps); d <= TOTPSkewSteps; d++ {
		s := step + d
		if s <= lastStep || s < 0 {
			continue
		}
		ok, err := hotp.ValidateCustom(code, uint64(s), secret, hotp.ValidateOpts{Digits: otp.DigitsSix, Algorithm: otp.AlgorithmSHA1})
		if err == nil && ok {
			return s, true
		}
	}
	return 0, false
}

// SealKeyBytes is the length of the ANSP_SECRETS_KEY_FILE key.
const SealKeyBytes = 32

// Sealer seals secrets at rest with AES-256-GCM under the key of
// ANSP_SECRETS_KEY_FILE: the TOTP secrets here, the occurrence
// reporter reference in WP-10. A sealed value is nonce || ciphertext,
// bound to its row by the additional data, and stored beside KeyID.
type Sealer struct {
	keyID string
	aead  cipher.AEAD
}

// LoadSealer reads the key file: 32 bytes as base64 or hex (trimmed).
func LoadSealer(path string) (*Sealer, error) {
	raw, err := readBounded("ANSP_SECRETS_KEY_FILE", path, 1024)
	if err != nil {
		return nil, err
	}
	text := strings.TrimSpace(string(raw))
	key, err := hex.DecodeString(text)
	if err != nil {
		key, err = base64.StdEncoding.DecodeString(text)
	}
	if err != nil || len(key) != SealKeyBytes {
		return nil, core.Fieldf("ANSP_SECRETS_KEY_FILE", "must hold %d random bytes as hex or base64", SealKeyBytes)
	}
	return NewSealer(key)
}

// NewSealer seals under key (SealKeyBytes long).
func NewSealer(key []byte) (*Sealer, error) {
	if len(key) != SealKeyBytes {
		return nil, errors.New("the sealing key must be 32 bytes")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(key)
	return &Sealer{keyID: hex.EncodeToString(sum[:8]), aead: aead}, nil
}

// KeyID names the key (the first 8 bytes of its SHA-256, hex): what
// user_mfa.key_id stores, never the key.
func (s *Sealer) KeyID() string { return s.keyID }

// Seal encrypts plaintext bound to aad.
func (s *Sealer) Seal(plaintext, aad []byte) ([]byte, error) {
	nonce := make([]byte, s.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return s.aead.Seal(nonce, nonce, plaintext, aad), nil
}

// ErrSealedKey is a sealed value under another key, or one that does
// not open.
var ErrSealedKey = errors.New("the sealed value does not open under the configured key")

// Open decrypts a value sealed under keyID with aad.
func (s *Sealer) Open(keyID string, sealed, aad []byte) ([]byte, error) {
	n := s.aead.NonceSize()
	if keyID != s.keyID || len(sealed) < n+s.aead.Overhead() {
		return nil, ErrSealedKey
	}
	out, err := s.aead.Open(nil, sealed[:n], sealed[n:], aad)
	if err != nil {
		return nil, ErrSealedKey
	}
	return out, nil
}
