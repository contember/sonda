package issuer

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

type memoryStore struct {
	keys []Key
}

func (m *memoryStore) SigningKeys(context.Context) ([]Key, error) { return m.keys, nil }

func (m *memoryStore) AddSigningKey(_ context.Context, key Key) error {
	m.keys = append(m.keys, key)
	return nil
}

func getJSON(t *testing.T, url string, out any) {
	t.Helper()
	resp, err := http.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET %s: %s", url, resp.Status)
	}
	if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
		t.Fatal(err)
	}
}

// verify checks the token's signature against the served JWKS, as a relying party does, and
// returns its claims.
func verify(t *testing.T, token string, jwks []jwk) map[string]any {
	t.Helper()
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("token has %d parts", len(parts))
	}
	var header map[string]string
	decodePart(t, parts[0], &header)
	if header["alg"] != "RS256" {
		t.Fatalf("alg = %q", header["alg"])
	}
	var key *jwk
	for i := range jwks {
		if jwks[i].KeyID == header["kid"] {
			key = &jwks[i]
		}
	}
	if key == nil {
		t.Fatalf("kid %q is not in the JWKS", header["kid"])
	}
	n, _ := base64.RawURLEncoding.DecodeString(key.N)
	e, _ := base64.RawURLEncoding.DecodeString(key.E)
	public := &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: int(new(big.Int).SetBytes(e).Int64())}
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if err := rsa.VerifyPKCS1v15(public, crypto.SHA256, digest[:], signature); err != nil {
		t.Fatalf("signature does not verify: %v", err)
	}
	var claims map[string]any
	decodePart(t, parts[1], &claims)
	return claims
}

func decodePart(t *testing.T, part string, out any) {
	t.Helper()
	data, err := base64.RawURLEncoding.DecodeString(part)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, out); err != nil {
		t.Fatal(err)
	}
}

func TestTokenVerifiesAgainstServedJWKS(t *testing.T) {
	mux := http.NewServeMux()
	server := httptest.NewServer(mux)
	defer server.Close()
	issuerURL := server.URL + "/sonda"
	store := &memoryStore{}
	iss, err := Open(context.Background(), issuerURL, store)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_800_000_000, 0)
	iss.now = func() time.Time { return now }
	if err := iss.Mount(mux); err != nil {
		t.Fatal(err)
	}

	var discovery struct {
		Issuer  string `json:"issuer"`
		JWKSURI string `json:"jwks_uri"`
	}
	getJSON(t, issuerURL+"/.well-known/openid-configuration", &discovery)
	if discovery.Issuer != issuerURL || discovery.JWKSURI != issuerURL+"/.well-known/jwks.json" {
		t.Fatalf("discovery = %+v", discovery)
	}
	var set struct {
		Keys []jwk `json:"keys"`
	}
	getJSON(t, discovery.JWKSURI, &set)

	token, err := iss.Token("sts.amazonaws.com")
	if err != nil {
		t.Fatal(err)
	}
	claims := verify(t, token, set.Keys)
	want := map[string]any{
		"iss": issuerURL, "sub": "sonda", "aud": "sts.amazonaws.com",
		"iat": float64(now.Unix()), "nbf": float64(now.Unix()), "exp": float64(now.Add(5 * time.Minute).Unix()),
	}
	for name, value := range want {
		if claims[name] != value {
			t.Errorf("claim %s = %v, want %v", name, claims[name], value)
		}
	}
}

func TestOpenReusesStoredKeyAndPublishesAll(t *testing.T) {
	store := &memoryStore{}
	first, err := Open(context.Background(), "https://sonda.example.com", store)
	if err != nil {
		t.Fatal(err)
	}
	second, err := Open(context.Background(), "https://sonda.example.com", store)
	if err != nil {
		t.Fatal(err)
	}
	if len(store.keys) != 1 || first.keyID != second.keyID {
		t.Fatalf("restart created another key: %d keys", len(store.keys))
	}

	// Another replica added a newer key: this one signs with it and the JWKS lists both.
	newer, err := newKey(time.Now())
	if err != nil {
		t.Fatal(err)
	}
	store.keys = append(store.keys, newer)
	third, err := Open(context.Background(), "https://sonda.example.com", store)
	if err != nil {
		t.Fatal(err)
	}
	if third.keyID != newer.ID {
		t.Errorf("signing key = %s, want the newest %s", third.keyID, newer.ID)
	}
	data, err := first.jwks(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	var set struct {
		Keys []jwk `json:"keys"`
	}
	if err := json.Unmarshal(data, &set); err != nil {
		t.Fatal(err)
	}
	token, err := third.Token("sts.amazonaws.com")
	if err != nil {
		t.Fatal(err)
	}
	if len(set.Keys) != 2 {
		t.Fatalf("JWKS has %d keys, want 2", len(set.Keys))
	}
	verify(t, token, set.Keys)
}

func TestThumbprintMatchesRFC7638(t *testing.T) {
	n, _ := base64.RawURLEncoding.DecodeString("0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw")
	key := &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: 65537}
	if got := thumbprint(key); got != "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs" {
		t.Errorf("thumbprint = %s", got)
	}
}
