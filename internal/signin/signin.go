// Package signin signs people in to the admin UI through an OAuth 2.1 authorization server:
// the authorization code flow with PKCE (RFC 7636) for one resource (RFC 8707), and an access
// token verified as an RFC 9068 JWT against the server's published keys. Sonda is a public
// client identified by a client ID metadata document that it serves itself.
//
// The authorization server authenticates the person and may name their role in Sonda (the roles
// claim). What data they may query is decided by Sonda: the grants of the identity their subject
// is linked to.
package signin

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/contember/sonda/internal/config"
)

const (
	ClientPath   = "/admin/oauth/client"
	CallbackPath = "/admin/oauth/callback"
	// ResourcePath is appended to the public URL to name the admin UI as an RFC 8707 resource.
	ResourcePath = "/admin"

	metadataPath = "/.well-known/oauth-authorization-server"
	// clockSkew tolerates a small difference between Sonda's and the server's clocks.
	clockSkew = 30 * time.Second
	// keysMaxAge refetches the keys this often, so a key the server withdrew stops verifying.
	keysMaxAge = time.Hour
	// keysMinInterval limits refetches caused by tokens with an unknown key ID.
	keysMinInterval  = 30 * time.Second
	maxDocumentBytes = 1 << 20
)

// Client is safe for concurrent use.
type Client struct {
	issuer      string
	clientID    string
	redirectURI string
	resource    string
	http        *http.Client
	now         func() time.Time

	mu          sync.Mutex
	metadata    *serverMetadata
	keys        map[string]*ecdsa.PublicKey
	keysFetched time.Time
}

func New(cfg config.AdminOAuth, httpClient *http.Client) *Client {
	return &Client{
		issuer:      cfg.Issuer,
		clientID:    cfg.URL + ClientPath,
		redirectURI: cfg.URL + CallbackPath,
		resource:    cfg.URL + ResourcePath,
		http:        httpClient,
		now:         time.Now,
	}
}

func (c *Client) Issuer() string   { return c.issuer }
func (c *Client) ClientID() string { return c.clientID }
func (c *Client) Resource() string { return c.resource }

// ClientMetadata is the client ID metadata document served at the client ID.
type ClientMetadata struct {
	ClientID                string   `json:"client_id"`
	ClientName              string   `json:"client_name"`
	RedirectURIs            []string `json:"redirect_uris"`
	GrantTypes              []string `json:"grant_types"`
	ResponseTypes           []string `json:"response_types"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
}

func (c *Client) ClientMetadata() ClientMetadata {
	return ClientMetadata{
		ClientID:                c.clientID,
		ClientName:              "Sonda admin",
		RedirectURIs:            []string{c.redirectURI},
		GrantTypes:              []string{"authorization_code"},
		ResponseTypes:           []string{"code"},
		TokenEndpointAuthMethod: "none",
	}
}

// Attempt is one sign-in in flight: State is sent to the server and Verifier stays with the
// browser in a cookie until the callback.
type Attempt struct {
	State    string
	Verifier string
}

func NewAttempt() Attempt {
	return Attempt{State: randomString(), Verifier: randomString()}
}

// Matches reports whether the callback's state belongs to this attempt.
func (a Attempt) Matches(state string) bool {
	return a.State != "" && subtle.ConstantTimeCompare([]byte(a.State), []byte(state)) == 1
}

func randomString() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

// AuthorizationURL is where the browser goes to sign in.
func (c *Client) AuthorizationURL(ctx context.Context, attempt Attempt) (string, error) {
	meta, err := c.serverMetadata(ctx)
	if err != nil {
		return "", err
	}
	challenge := sha256.Sum256([]byte(attempt.Verifier))
	query := url.Values{
		"response_type":         {"code"},
		"client_id":             {c.clientID},
		"redirect_uri":          {c.redirectURI},
		"resource":              {c.resource},
		"state":                 {attempt.State},
		"code_challenge":        {base64.RawURLEncoding.EncodeToString(challenge[:])},
		"code_challenge_method": {"S256"},
	}
	return meta.AuthorizationEndpoint + "?" + query.Encode(), nil
}

// Role keys of the roles claim (fabrika IAM: the roles an external application declares).
const (
	AdminRoleKey  = "sonda-admin"
	ViewerRoleKey = "sonda-viewer"
)

// Role is what the token's roles claim makes the person in Sonda.
type Role string

const (
	// RoleUnset: the token has no roles claim, so the person's link in Sonda decides.
	RoleUnset Role = ""
	// RoleNone: the token names roles, none of them Sonda's; the person is refused.
	RoleNone Role = "none"
	// RoleAdmin manages Sonda, with or without a link to an identity.
	RoleAdmin Role = "admin"
	// RoleViewer sees My access of the identity their subject is linked to.
	RoleViewer Role = "viewer"
)

func roleOf(roles *[]string) Role {
	switch {
	case roles == nil:
		return RoleUnset
	case slices.Contains(*roles, AdminRoleKey):
		return RoleAdmin
	case slices.Contains(*roles, ViewerRoleKey):
		return RoleViewer
	}
	return RoleNone
}

// Person is who the server signed in.
type Person struct {
	Subject string
	// Label is the server's display name for the person, possibly empty. It identifies nobody.
	Label string
	Role  Role
}

// Callback is what the server sent back to the redirect URI.
type Callback struct {
	Code string
	// Issuer is the RFC 9207 iss parameter, empty when the server did not send it.
	Issuer string
}

// Exchange redeems the code and verifies the access token it returns.
func (c *Client) Exchange(ctx context.Context, cb Callback, attempt Attempt) (Person, error) {
	meta, err := c.serverMetadata(ctx)
	if err != nil {
		return Person{}, err
	}
	// RFC 9207: a response from another server must not be redeemed here (mix-up attack).
	if cb.Issuer != "" && cb.Issuer != c.issuer || cb.Issuer == "" && meta.IssuerParameterSupported {
		return Person{}, fmt.Errorf("authorization response issuer %q does not match %q", cb.Issuer, c.issuer)
	}
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"client_id":     {c.clientID},
		"code":          {cb.Code},
		"redirect_uri":  {c.redirectURI},
		"code_verifier": {attempt.Verifier},
		"resource":      {c.resource},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, meta.TokenEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return Person{}, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	var response struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
		Error       string `json:"error"`
	}
	status, err := c.doJSON(req, &response)
	if err != nil {
		return Person{}, fmt.Errorf("token request: %w", err)
	}
	if status != http.StatusOK {
		return Person{}, fmt.Errorf("token request: status %d, error %q", status, response.Error)
	}
	if !strings.EqualFold(response.TokenType, "Bearer") || response.AccessToken == "" {
		return Person{}, errors.New("token response has no bearer access token")
	}
	return c.Verify(ctx, response.AccessToken)
}

// Verify checks an access token issued for this client and resource to a person.
func (c *Client) Verify(ctx context.Context, token string) (Person, error) {
	encodedHeader, rest, _ := strings.Cut(token, ".")
	encodedPayload, encodedSignature, _ := strings.Cut(rest, ".")
	var header struct {
		Alg string `json:"alg"`
		Typ string `json:"typ"`
		Kid string `json:"kid"`
	}
	if err := decodeSegment(encodedHeader, &header); err != nil {
		return Person{}, fmt.Errorf("token header: %w", err)
	}
	// RFC 9068 §4: an access token is typed, so an ID token or another JWT is not taken for one.
	if header.Alg != "ES256" || !isAccessTokenType(header.Typ) {
		return Person{}, fmt.Errorf("token alg %q, typ %q: want ES256 at+jwt", header.Alg, header.Typ)
	}
	signature, err := base64.RawURLEncoding.DecodeString(encodedSignature)
	if err != nil || len(signature) != 64 {
		return Person{}, errors.New("token signature is not an ES256 signature")
	}
	key, err := c.key(ctx, header.Kid)
	if err != nil {
		return Person{}, err
	}
	digest := sha256.Sum256([]byte(encodedHeader + "." + encodedPayload))
	r, s := new(big.Int).SetBytes(signature[:32]), new(big.Int).SetBytes(signature[32:])
	if !ecdsa.Verify(key, digest[:], r, s) {
		return Person{}, errors.New("token signature does not verify")
	}

	var claims struct {
		Issuer   string   `json:"iss"`
		Audience audience `json:"aud"`
		Subject  string   `json:"sub"`
		Expiry   *float64 `json:"exp"`
		ClientID string   `json:"client_id"`
		// The principal type is a claim of the issuer this client is built for; a token without
		// it, or for anything but a user, signs in nobody.
		PrincipalType string `json:"ptype"`
		Label         string `json:"label"`
		// Roles is nil when the claim is absent; a claim that is not an array of strings fails
		// the decode and refuses the token.
		Roles *[]string `json:"roles"`
	}
	if err := decodeSegment(encodedPayload, &claims); err != nil {
		return Person{}, fmt.Errorf("token payload: %w", err)
	}
	now := c.now()
	switch {
	case claims.Issuer != c.issuer:
		return Person{}, fmt.Errorf("token issuer %q, want %q", claims.Issuer, c.issuer)
	case !slices.Contains(claims.Audience, c.resource):
		return Person{}, fmt.Errorf("token audience %q does not include %q", claims.Audience, c.resource)
	case claims.ClientID != c.clientID:
		return Person{}, fmt.Errorf("token client %q, want %q", claims.ClientID, c.clientID)
	case claims.Expiry == nil || !now.Before(time.Unix(int64(*claims.Expiry), 0).Add(clockSkew)):
		return Person{}, errors.New("token expired")
	case claims.Subject == "":
		return Person{}, errors.New("token has no subject")
	case claims.PrincipalType != "user":
		return Person{}, fmt.Errorf("token principal type %q, want user", claims.PrincipalType)
	}
	return Person{Subject: claims.Subject, Label: claims.Label, Role: roleOf(claims.Roles)}, nil
}

func isAccessTokenType(typ string) bool {
	return strings.EqualFold(typ, "at+jwt") || strings.EqualFold(typ, "application/at+jwt")
}

// audience is the aud claim, a string or an array of strings.
type audience []string

func (a *audience) UnmarshalJSON(data []byte) error {
	var one string
	if err := json.Unmarshal(data, &one); err == nil {
		*a = audience{one}
		return nil
	}
	var many []string
	if err := json.Unmarshal(data, &many); err != nil {
		return errors.New("aud is neither a string nor an array of strings")
	}
	*a = many
	return nil
}

func decodeSegment(segment string, v any) error {
	data, err := base64.RawURLEncoding.DecodeString(segment)
	if err != nil {
		return err
	}
	return json.Unmarshal(data, v)
}

type serverMetadata struct {
	Issuer                   string   `json:"issuer"`
	AuthorizationEndpoint    string   `json:"authorization_endpoint"`
	TokenEndpoint            string   `json:"token_endpoint"`
	JWKSURI                  string   `json:"jwks_uri"`
	IssuerParameterSupported bool     `json:"authorization_response_iss_parameter_supported"`
	CodeChallengeMethods     []string `json:"code_challenge_methods_supported"`
}

// serverMetadata fetches the RFC 8414 metadata once; a failed fetch is retried next time.
func (c *Client) serverMetadata(ctx context.Context) (*serverMetadata, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.metadata != nil {
		return c.metadata, nil
	}
	issuerURL, err := url.Parse(c.issuer)
	if err != nil {
		return nil, err
	}
	// RFC 8414 §3.1: the well-known segment goes between the host and the issuer's path.
	metadataURL := issuerURL.Scheme + "://" + issuerURL.Host + metadataPath + issuerURL.Path
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, metadataURL, nil)
	if err != nil {
		return nil, err
	}
	var meta serverMetadata
	status, err := c.doJSON(req, &meta)
	if err != nil || status != http.StatusOK {
		return nil, fmt.Errorf("authorization server metadata %s: status %d: %v", metadataURL, status, err)
	}
	if meta.Issuer != c.issuer {
		return nil, fmt.Errorf("authorization server metadata names issuer %q, want %q", meta.Issuer, c.issuer)
	}
	if !slices.Contains(meta.CodeChallengeMethods, "S256") {
		return nil, errors.New("authorization server does not support PKCE with S256")
	}
	for name, endpoint := range map[string]string{"authorization_endpoint": meta.AuthorizationEndpoint, "token_endpoint": meta.TokenEndpoint, "jwks_uri": meta.JWKSURI} {
		if !sameScheme(endpoint, c.issuer) {
			return nil, fmt.Errorf("authorization server metadata: %s %q is not a URL with the issuer's scheme", name, endpoint)
		}
	}
	c.metadata = &meta
	return c.metadata, nil
}

// sameScheme accepts an absolute URL with the issuer's scheme, so an https issuer never
// sends a code or verifier over plain http.
func sameScheme(endpoint, issuer string) bool {
	u, err := url.Parse(endpoint)
	i, _ := url.Parse(issuer)
	return err == nil && u.Host != "" && u.User == nil && u.Fragment == "" && u.Scheme == i.Scheme
}

// key returns the server's verification key with the ID, refetching the key set when the ID
// is unknown or the set is old.
func (c *Client) key(ctx context.Context, kid string) (*ecdsa.PublicKey, error) {
	meta, err := c.serverMetadata(ctx)
	if err != nil {
		return nil, err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.now()
	key, known := c.keys[kid]
	stale := now.Sub(c.keysFetched) > keysMaxAge
	if known && !stale {
		return key, nil
	}
	if stale || now.Sub(c.keysFetched) > keysMinInterval {
		keys, err := c.fetchKeys(ctx, meta.JWKSURI)
		if err != nil {
			return nil, err
		}
		c.keys, c.keysFetched = keys, now
	}
	if key, ok := c.keys[kid]; ok {
		return key, nil
	}
	return nil, fmt.Errorf("token key %q is not published by the authorization server", kid)
}

func (c *Client) fetchKeys(ctx context.Context, jwksURI string) (map[string]*ecdsa.PublicKey, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, jwksURI, nil)
	if err != nil {
		return nil, err
	}
	var set struct {
		Keys []struct {
			Kty string `json:"kty"`
			Crv string `json:"crv"`
			Kid string `json:"kid"`
			Use string `json:"use"`
			X   string `json:"x"`
			Y   string `json:"y"`
		} `json:"keys"`
	}
	status, err := c.doJSON(req, &set)
	if err != nil || status != http.StatusOK {
		return nil, fmt.Errorf("authorization server keys %s: status %d: %v", jwksURI, status, err)
	}
	keys := map[string]*ecdsa.PublicKey{}
	for _, k := range set.Keys {
		// Keys of other types or for encryption are not ours to use; skip them.
		if k.Kty != "EC" || k.Crv != "P-256" || (k.Use != "" && k.Use != "sig") {
			continue
		}
		x, errX := base64.RawURLEncoding.DecodeString(k.X)
		y, errY := base64.RawURLEncoding.DecodeString(k.Y)
		if errX != nil || errY != nil || len(x) != 32 || len(y) != 32 {
			return nil, fmt.Errorf("authorization server key %q is not a P-256 point", k.Kid)
		}
		key, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), slices.Concat([]byte{4}, x, y))
		if err != nil {
			return nil, fmt.Errorf("authorization server key %q: %w", k.Kid, err)
		}
		keys[k.Kid] = key
	}
	return keys, nil
}

// doJSON decodes a JSON response of any status, so an OAuth error body is readable too.
func (c *Client) doJSON(req *http.Request, v any) (int, error) {
	resp, err := c.http.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxDocumentBytes))
	if err != nil {
		return resp.StatusCode, err
	}
	if err := json.Unmarshal(body, v); err != nil {
		return resp.StatusCode, fmt.Errorf("decode response: %w", err)
	}
	return resp.StatusCode, nil
}
