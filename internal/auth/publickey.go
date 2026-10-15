package auth

import (
	"bytes"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strings"

	coreauth "github.com/rootxkit/uspace-core/auth"
	"github.com/rootxkit/uspace-core/core"
)

// LoadPublicKeyFile reads path, a PEM file holding one RSA public key
// (SubjectPublicKeyInfo "PUBLIC KEY", as `openssl pkey -pubout` writes
// it, or PKCS #1 "RSA PUBLIC KEY"), at least coreauth.MinRSABits long.
// A private key is refused: the process that verifies with this file
// must never hold the key that signs. field names the variable in
// errors, which never quote the content.
func LoadPublicKeyFile(field, path string) (*rsa.PublicKey, error) {
	raw, err := readBounded(field, path, MaxKeyFileBytes)
	if err != nil {
		return nil, err
	}
	pub, err := ParsePublicKeyPEM(raw)
	if err != nil {
		return nil, core.Fieldf(field, "%v", err)
	}
	return pub, nil
}

// ParsePublicKeyPEM parses exactly one PEM block holding an RSA public
// key of at least coreauth.MinRSABits. A private key block is refused
// by name.
func ParsePublicKeyPEM(raw []byte) (*rsa.PublicKey, error) {
	block, rest := pem.Decode(raw)
	if block == nil {
		return nil, errors.New("no PEM block")
	}
	if strings.TrimSpace(string(rest)) != "" {
		return nil, errors.New("more than one PEM block")
	}
	var pub *rsa.PublicKey
	switch block.Type {
	case "PUBLIC KEY":
		k, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, errors.New("not a SubjectPublicKeyInfo public key")
		}
		rk, ok := k.(*rsa.PublicKey)
		if !ok {
			return nil, fmt.Errorf("a %T, not an RSA key (RS256 only)", k)
		}
		pub = rk
	case "RSA PUBLIC KEY":
		k, err := x509.ParsePKCS1PublicKey(block.Bytes)
		if err != nil {
			return nil, errors.New("not a PKCS #1 RSA public key")
		}
		pub = k
	case "RSA PRIVATE KEY", "PRIVATE KEY", "ENCRYPTED PRIVATE KEY":
		return nil, errors.New("a private key: give this process the public part only (openssl pkey -pubout)")
	default:
		return nil, fmt.Errorf("PEM block %q is not a public key", block.Type)
	}
	if bits := pub.N.BitLen(); bits < coreauth.MinRSABits {
		return nil, fmt.Errorf("the key is %d bits, shorter than %d", bits, coreauth.MinRSABits)
	}
	return pub, nil
}

// publicKeyJWKSURL is where the verifier of a public-key session ring
// "fetches" its key set. Nothing is fetched: the verifier's HTTP client
// answers this one URL from memory (staticJWKS) and refuses every
// other, so the name never resolves (.invalid, RFC 2606).
const publicKeyJWKSURL = "https://session-key.invalid/.well-known/jwks.json"

// publicKeyJWKS is the RFC 7517 set holding pub alone, as api's
// /.well-known/jwks.json publishes the session key: kid its RFC 7638
// thumbprint (the kid api signs with), alg RS256, use sig. Core parses
// and judges it as it judges any published JWKS (alg, use, size).
func publicKeyJWKS(pub *rsa.PublicKey) ([]byte, error) {
	b64 := base64.RawURLEncoding
	return json.Marshal(map[string]any{"keys": []map[string]string{{
		"kty": "RSA",
		"kid": Thumbprint(pub),
		"alg": "RS256",
		"use": "sig",
		"n":   b64.EncodeToString(pub.N.Bytes()),
		"e":   b64.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
	}}})
}

// staticJWKS is an http.RoundTripper that answers GET publicKeyJWKSURL
// with body and refuses every other request: the core verifier, which
// takes static keys only as a jwk.Set, reads the session key from
// memory and never from the network.
type staticJWKS struct{ body []byte }

// RoundTrip answers the one URL of the session key set.
func (s staticJWKS) RoundTrip(r *http.Request) (*http.Response, error) {
	if r.Body != nil {
		_ = r.Body.Close()
	}
	if r.Method != http.MethodGet || r.URL.String() != publicKeyJWKSURL {
		return nil, errors.New("the session key set is served from memory only")
	}
	return &http.Response{
		Status: "200 OK", StatusCode: http.StatusOK, Proto: "HTTP/1.1", ProtoMajor: 1, ProtoMinor: 1,
		Header:        http.Header{"Content-Type": []string{"application/jwk-set+json"}},
		Body:          io.NopCloser(bytes.NewReader(s.body)),
		ContentLength: int64(len(s.body)), Request: r,
	}, nil
}

// publicKeyIssuer is the core issuer configuration and HTTP client that
// verify sessions with pub alone.
func publicKeyIssuer(pub *rsa.PublicKey) (coreauth.IssuerConfig, *http.Client, error) {
	body, err := publicKeyJWKS(pub)
	if err != nil {
		return coreauth.IssuerConfig{}, nil, err
	}
	client := &http.Client{Transport: staticJWKS{body: body},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	return coreauth.IssuerConfig{JWKSURL: publicKeyJWKSURL}, client, nil
}
