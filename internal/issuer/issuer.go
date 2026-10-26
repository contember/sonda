// Package issuer makes Sonda an OpenID Connect issuer of its own workload identity. It signs
// short-lived tokens that a cloud provider trusts through the issuer URL, e.g. AWS STS
// AssumeRoleWithWebIdentity, so Sonda needs no long-lived cloud credentials and no identity
// from the platform it runs on.
package issuer

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/url"
	"time"
)

const (
	// Subject is the sub claim of every token; trust policies match it.
	Subject       = "sonda"
	tokenLifetime = 5 * time.Minute
	keyBits       = 2048

	discoveryPath = "/.well-known/openid-configuration"
	jwksPath      = "/.well-known/jwks.json"
)

// Key is a signing key as stored: ID is its RFC 7638 thumbprint, PrivateKey PKCS #8 DER.
type Key struct {
	ID         string
	PrivateKey []byte
	CreatedAt  time.Time
}

// KeyStore keeps the signing keys. Keys are shared by all replicas of a Sonda.
type KeyStore interface {
	// SigningKeys returns all keys, oldest first.
	SigningKeys(ctx context.Context) ([]Key, error)
	AddSigningKey(ctx context.Context, key Key) error
}

type Issuer struct {
	url   string
	store KeyStore
	key   *rsa.PrivateKey
	keyID string
	now   func() time.Time
}

// Open signs with the newest stored key and creates the first key when there is none. The
// JWKS lists every stored key, so tokens of a replica that created another key still verify.
func Open(ctx context.Context, issuerURL string, store KeyStore) (*Issuer, error) {
	keys, err := store.SigningKeys(ctx)
	if err != nil {
		return nil, fmt.Errorf("load signing keys: %w", err)
	}
	if len(keys) == 0 {
		key, err := newKey(time.Now())
		if err != nil {
			return nil, err
		}
		if err := store.AddSigningKey(ctx, key); err != nil {
			return nil, fmt.Errorf("store signing key: %w", err)
		}
		keys = []Key{key}
	}
	newest := keys[len(keys)-1]
	private, err := parseKey(newest)
	if err != nil {
		return nil, err
	}
	return &Issuer{url: issuerURL, store: store, key: private, keyID: newest.ID, now: time.Now}, nil
}

func newKey(now time.Time) (Key, error) {
	private, err := rsa.GenerateKey(rand.Reader, keyBits)
	if err != nil {
		return Key{}, err
	}
	der, err := x509.MarshalPKCS8PrivateKey(private)
	if err != nil {
		return Key{}, err
	}
	return Key{ID: thumbprint(&private.PublicKey), PrivateKey: der, CreatedAt: now}, nil
}

func parseKey(key Key) (*rsa.PrivateKey, error) {
	parsed, err := x509.ParsePKCS8PrivateKey(key.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("signing key %s: %w", key.ID, err)
	}
	private, ok := parsed.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("signing key %s is not an RSA key", key.ID)
	}
	return private, nil
}

// Token returns a signed token for audience, e.g. sts.amazonaws.com.
func (i *Issuer) Token(audience string) (string, error) {
	now := i.now()
	header, err := json.Marshal(map[string]string{"alg": "RS256", "typ": "JWT", "kid": i.keyID})
	if err != nil {
		return "", err
	}
	claims, err := json.Marshal(map[string]any{
		"iss": i.url,
		"sub": Subject,
		"aud": audience,
		"iat": now.Unix(),
		"nbf": now.Unix(),
		"exp": now.Add(tokenLifetime).Unix(),
	})
	if err != nil {
		return "", err
	}
	signingInput := encode(header) + "." + encode(claims)
	digest := sha256.Sum256([]byte(signingInput))
	signature, err := rsa.SignPKCS1v15(rand.Reader, i.key, crypto.SHA256, digest[:])
	if err != nil {
		return "", err
	}
	return signingInput + "." + encode(signature), nil
}

// Mount serves the discovery document and the JWKS under the issuer URL's path.
func (i *Issuer) Mount(mux *http.ServeMux) error {
	u, err := url.Parse(i.url)
	if err != nil {
		return err
	}
	discovery, err := json.Marshal(map[string]any{
		"issuer":                                i.url,
		"jwks_uri":                              i.url + jwksPath,
		"response_types_supported":              []string{"id_token"},
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": []string{"RS256"},
		"claims_supported":                      []string{"iss", "sub", "aud", "iat", "nbf", "exp"},
	})
	if err != nil {
		return err
	}
	mux.HandleFunc("GET "+u.Path+discoveryPath, func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, discovery)
	})
	mux.HandleFunc("GET "+u.Path+jwksPath, func(w http.ResponseWriter, r *http.Request) {
		jwks, err := i.jwks(r.Context())
		if err != nil {
			http.Error(w, "signing keys are unavailable", http.StatusInternalServerError)
			return
		}
		writeJSON(w, jwks)
	})
	return nil
}

type jwk struct {
	KeyType   string `json:"kty"`
	Use       string `json:"use"`
	Algorithm string `json:"alg"`
	KeyID     string `json:"kid"`
	N         string `json:"n"`
	E         string `json:"e"`
}

func (i *Issuer) jwks(ctx context.Context) ([]byte, error) {
	keys, err := i.store.SigningKeys(ctx)
	if err != nil {
		return nil, err
	}
	set := struct {
		Keys []jwk `json:"keys"`
	}{Keys: []jwk{}}
	for _, key := range keys {
		private, err := parseKey(key)
		if err != nil {
			return nil, err
		}
		n, e := publicParts(&private.PublicKey)
		set.Keys = append(set.Keys, jwk{KeyType: "RSA", Use: "sig", Algorithm: "RS256", KeyID: key.ID, N: n, E: e})
	}
	return json.Marshal(set)
}

func writeJSON(w http.ResponseWriter, body []byte) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "public, max-age=300")
	_, _ = w.Write(body)
}

func publicParts(key *rsa.PublicKey) (n, e string) {
	return encode(key.N.Bytes()), encode(big.NewInt(int64(key.E)).Bytes())
}

// thumbprint is the RFC 7638 JWK thumbprint, used as the key ID.
func thumbprint(key *rsa.PublicKey) string {
	n, e := publicParts(key)
	// RFC 7638 fixes the member order and the absence of whitespace.
	digest := sha256.Sum256([]byte(`{"e":"` + e + `","kty":"RSA","n":"` + n + `"}`))
	return encode(digest[:])
}

func encode(b []byte) string {
	return base64.RawURLEncoding.EncodeToString(b)
}
