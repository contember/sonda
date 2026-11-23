// Package signintest is a minimal OAuth 2.1 authorization server for tests: it signs in a
// configured person without asking, checks PKCE, and issues ES256 at+jwt access tokens.
package signintest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
	"time"
)

const KeyID = "test-key"

type Server struct {
	*httptest.Server
	key *ecdsa.PrivateKey

	mu      sync.Mutex
	subject string
	label   string
	codes   map[string]grant
	// Tamper, when set, changes the header and claims of the next tokens before signing.
	tamper func(header, claims map[string]any)
}

type grant struct {
	clientID, redirectURI, resource, challenge string
}

func New(t testing.TB) *Server {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	s := &Server{key: key, codes: map[string]grant{}}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/oauth-authorization-server", s.metadata)
	mux.HandleFunc("GET /jwks.json", s.jwks)
	mux.HandleFunc("GET /authorize", s.authorize)
	mux.HandleFunc("POST /token", s.token)
	s.Server = httptest.NewServer(mux)
	t.Cleanup(s.Close)
	return s
}

// SignIn makes the server sign in this person from now on.
func (s *Server) SignIn(subject, label string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.subject, s.label = subject, label
}

func (s *Server) Tamper(fn func(header, claims map[string]any)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tamper = fn
}

func (s *Server) metadata(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"issuer":                           s.URL,
		"authorization_endpoint":           s.URL + "/authorize",
		"token_endpoint":                   s.URL + "/token",
		"jwks_uri":                         s.URL + "/jwks.json",
		"response_types_supported":         []string{"code"},
		"code_challenge_methods_supported": []string{"S256"},
		"authorization_response_iss_parameter_supported": true,
	})
}

func (s *Server) jwks(w http.ResponseWriter, _ *http.Request) {
	point, err := s.key.PublicKey.Bytes()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"keys": []map[string]string{{
		"kty": "EC", "crv": "P-256", "kid": KeyID, "use": "sig", "alg": "ES256",
		"x": base64.RawURLEncoding.EncodeToString(point[1:33]),
		"y": base64.RawURLEncoding.EncodeToString(point[33:]),
	}}})
}

func (s *Server) authorize(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	if q.Get("response_type") != "code" || q.Get("code_challenge_method") != "S256" || q.Get("code_challenge") == "" {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	code := random()
	s.mu.Lock()
	s.codes[code] = grant{clientID: q.Get("client_id"), redirectURI: q.Get("redirect_uri"), resource: q.Get("resource"), challenge: q.Get("code_challenge")}
	s.mu.Unlock()
	target, err := url.Parse(q.Get("redirect_uri"))
	if err != nil {
		http.Error(w, "invalid redirect_uri", http.StatusBadRequest)
		return
	}
	params := url.Values{"code": {code}, "state": {q.Get("state")}, "iss": {s.URL}}
	target.RawQuery = params.Encode()
	http.Redirect(w, r, target.String(), http.StatusFound)
}

func (s *Server) token(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	code := r.PostFormValue("code")
	g, ok := s.codes[code]
	delete(s.codes, code)
	challenge := sha256.Sum256([]byte(r.PostFormValue("code_verifier")))
	if !ok || r.PostFormValue("grant_type") != "authorization_code" || r.PostFormValue("client_id") != g.clientID ||
		r.PostFormValue("redirect_uri") != g.redirectURI || r.PostFormValue("resource") != g.resource ||
		base64.RawURLEncoding.EncodeToString(challenge[:]) != g.challenge {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_grant"})
		return
	}
	now := time.Now()
	header := map[string]any{"alg": "ES256", "typ": "at+jwt", "kid": KeyID}
	claims := map[string]any{
		"iss": s.URL, "aud": g.resource, "sub": s.subject, "iat": now.Unix(), "exp": now.Add(5 * time.Minute).Unix(),
		"perms": []any{}, "ptype": "user", "label": s.label, "app": "sonda", "client_id": g.clientID,
		"scope": "sonda", "grant": "grant-1", "jti": random(),
	}
	if s.tamper != nil {
		s.tamper(header, claims)
	}
	writeJSON(w, http.StatusOK, map[string]any{"access_token": s.sign(header, claims), "token_type": "Bearer", "expires_in": 300, "scope": "sonda"})
}

// Sign signs a JWT with the server's key.
func (s *Server) Sign(header, claims map[string]any) string {
	return s.sign(header, claims)
}

func (s *Server) sign(header, claims map[string]any) string {
	h, _ := json.Marshal(header)
	c, _ := json.Marshal(claims)
	input := base64.RawURLEncoding.EncodeToString(h) + "." + base64.RawURLEncoding.EncodeToString(c)
	digest := sha256.Sum256([]byte(input))
	r, sig, err := ecdsa.Sign(rand.Reader, s.key, digest[:])
	if err != nil {
		panic(err)
	}
	signature := make([]byte, 64)
	r.FillBytes(signature[:32])
	sig.FillBytes(signature[32:])
	return input + "." + base64.RawURLEncoding.EncodeToString(signature)
}

func random() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
