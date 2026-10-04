package auth

import (
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"os"
	"slices"
	"strings"
	"sync"

	coreauth "github.com/rootxkit/uspace-core/auth"
	"github.com/rootxkit/uspace-core/core"

	"github.com/rootxkit/uspace-ansp/internal/apierr"
)

// MaxKeyFileBytes bounds a key file read at start.
const MaxKeyFileBytes = 64 << 10

// readBounded reads at most limit bytes of path; field names the
// variable in errors, which never quote the content.
func readBounded(field, path string, limit int) ([]byte, error) {
	f, err := os.Open(path) //nolint:gosec // the path is the operator's configuration
	if err != nil {
		var pe *os.PathError
		if errors.As(err, &pe) {
			err = pe.Err
		}
		return nil, core.Fieldf(field, "cannot be read: %v", err)
	}
	defer func() { _ = f.Close() }()
	raw, err := io.ReadAll(io.LimitReader(f, int64(limit)+1))
	if err != nil {
		return nil, core.Fieldf(field, "cannot be read")
	}
	if len(raw) > limit {
		return nil, core.Fieldf(field, "the file is larger than %d bytes", limit)
	}
	return raw, nil
}

// LoadKeyFile reads path, a PEM file holding one unencrypted RSA private
// key (PKCS #1 or PKCS #8), and returns it under its kid, the RFC 7638
// thumbprint. field names the variable in errors.
func LoadKeyFile(field, path string) (coreauth.SigningKey, error) {
	raw, err := readBounded(field, path, MaxKeyFileBytes)
	if err != nil {
		return coreauth.SigningKey{}, err
	}
	key, err := ParsePrivateKeyPEM(raw)
	if err != nil {
		return coreauth.SigningKey{}, core.Fieldf(field, "%v", err)
	}
	sk, err := NewSigningKey(key)
	if err != nil {
		return coreauth.SigningKey{}, core.Fieldf(field, "%v", err)
	}
	return sk, nil
}

// NewSigningKey checks key as core's issuer does (at least
// coreauth.MinRSABits, rsa Validate) and names it by its thumbprint.
func NewSigningKey(key *rsa.PrivateKey) (coreauth.SigningKey, error) {
	if key == nil {
		return coreauth.SigningKey{}, errors.New("no key")
	}
	if bits := key.N.BitLen(); bits < coreauth.MinRSABits {
		return coreauth.SigningKey{}, fmt.Errorf("the key is %d bits, shorter than %d", bits, coreauth.MinRSABits)
	}
	if err := key.Validate(); err != nil {
		return coreauth.SigningKey{}, errors.New("the RSA key does not validate")
	}
	return coreauth.SigningKey{KID: Thumbprint(&key.PublicKey), Key: key}, nil
}

// ParsePrivateKeyPEM parses exactly one PEM block holding an RSA private
// key. Encrypted PEM is refused.
func ParsePrivateKeyPEM(raw []byte) (*rsa.PrivateKey, error) {
	block, rest := pem.Decode(raw)
	if block == nil {
		return nil, errors.New("no PEM block")
	}
	if strings.TrimSpace(string(rest)) != "" {
		return nil, errors.New("more than one PEM block")
	}
	if _, enc := block.Headers["Proc-Type"]; enc {
		return nil, errors.New("encrypted PEM is not supported")
	}
	switch block.Type {
	case "RSA PRIVATE KEY":
		k, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, errors.New("not a PKCS #1 RSA private key")
		}
		return k, nil
	case "PRIVATE KEY":
		k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, errors.New("not a PKCS #8 private key")
		}
		rk, ok := k.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("a %T, not an RSA key (RS256 only)", k)
		}
		return rk, nil
	default:
		return nil, fmt.Errorf("PEM block %q is not a private key", block.Type)
	}
}

// Thumbprint is the RFC 7638 SHA-256 thumbprint of pub, base64url
// without padding: the hash of {"e","kty","n"} in that order, the
// integers as unsigned big-endian bytes without leading zeros.
func Thumbprint(pub *rsa.PublicKey) string {
	b64 := base64.RawURLEncoding
	e := b64.EncodeToString(big.NewInt(int64(pub.E)).Bytes())
	n := b64.EncodeToString(pub.N.Bytes())
	sum := sha256.Sum256([]byte(`{"e":"` + e + `","kty":"RSA","n":"` + n + `"}`))
	return b64.EncodeToString(sum[:])
}

// CounterJWKSRenderFailed counts a JWKS that could not be rendered.
const CounterJWKSRenderFailed = "jwks_render_failed"

// PublicKeys is the one place the JWKS of /.well-known/jwks.json is
// assembled (06 section 2 T4, M26): the console session key here and,
// from WP-8, the delivery-signing key, each a core KeyRing (rotation
// keeps a retired key published). A kid may appear in one ring only.
type PublicKeys struct {
	mu       sync.RWMutex
	names    []string
	rings    map[string]*coreauth.KeyRing
	counters core.Counters
}

// NewPublicKeys is an empty set.
func NewPublicKeys() *PublicKeys { return &PublicKeys{rings: map[string]*coreauth.KeyRing{}} }

// Add publishes ring under name (session, delivery). A name added twice
// and a kid already published by another ring are refused.
func (p *PublicKeys) Add(name string, ring *coreauth.KeyRing) error {
	if ring == nil || name == "" {
		return errors.New("a named key ring is required")
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if _, dup := p.rings[name]; dup {
		return fmt.Errorf("the key ring %s is already published", name)
	}
	for _, other := range p.names {
		for _, kid := range ring.KIDs() {
			if slices.Contains(p.rings[other].KIDs(), kid) {
				return fmt.Errorf("kid %s is published by %s already", kid, other)
			}
		}
	}
	p.names = append(p.names, name)
	p.rings[name] = ring
	return nil
}

// Counters are the endpoint's counters.
func (p *PublicKeys) Counters() *core.Counters { return &p.counters }

// Names is the rings published, in the order they were added.
func (p *PublicKeys) Names() []string {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return slices.Clone(p.names)
}

// JSON is the JWKS {"keys": [...]}: every key of every ring, public
// parts only, as core renders them, in the order the rings were added.
func (p *PublicKeys) JSON() ([]byte, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	keys := []json.RawMessage{}
	for _, name := range p.names {
		raw, err := json.Marshal(p.rings[name].JWKS())
		if err != nil {
			return nil, err
		}
		var set struct {
			Keys []json.RawMessage `json:"keys"`
		}
		if err := json.Unmarshal(raw, &set); err != nil {
			return nil, err
		}
		keys = append(keys, set.Keys...)
	}
	return json.Marshal(map[string]any{"keys": keys})
}

// ServeHTTP serves the JWKS (public, cacheable for five minutes).
func (p *PublicKeys) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, err := p.JSON()
	if err != nil {
		p.counters.Inc(CounterJWKSRenderFailed)
		apierr.NoteCause(r, fmt.Errorf("render the key set: %w", err))
		apierr.WriteError(w, r, refusal(http.StatusInternalServerError, SlugInternal, "the key set could not be rendered"))
		return
	}
	w.Header().Set("Content-Type", "application/jwk-set+json")
	w.Header().Set("Cache-Control", "public, max-age=300")
	_, _ = w.Write(body)
}
