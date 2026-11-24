package signin_test

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/contember/sonda/internal/config"
	"github.com/contember/sonda/internal/signin"
	"github.com/contember/sonda/internal/signin/signintest"
)

const sondaURL = "https://sonda.example.com"

func newClient(t *testing.T) (*signin.Client, *signintest.Server) {
	t.Helper()
	server := signintest.New(t)
	return signin.New(config.AdminOAuth{Issuer: server.URL, URL: sondaURL}, server.Client()), server
}

func validToken(server *signintest.Server, change func(header, claims map[string]any)) string {
	now := time.Now()
	header := map[string]any{"alg": "ES256", "typ": "at+jwt", "kid": signintest.KeyID}
	claims := map[string]any{
		"iss": server.URL, "aud": sondaURL + "/admin", "sub": "principal-1", "exp": now.Add(5 * time.Minute).Unix(),
		"ptype": "user", "label": "alice@example.com", "client_id": sondaURL + "/admin/oauth/client",
	}
	if change != nil {
		change(header, claims)
	}
	return server.Sign(header, claims)
}

func TestVerifyAcceptsAnAccessTokenForThisClientAndResource(t *testing.T) {
	client, server := newClient(t)
	person, err := client.Verify(context.Background(), validToken(server, nil))
	if err != nil {
		t.Fatal(err)
	}
	if person.Subject != "principal-1" || person.Label != "alice@example.com" {
		t.Errorf("person = %+v", person)
	}
	// aud may also be an array.
	if _, err := client.Verify(context.Background(), validToken(server, func(_, c map[string]any) {
		c["aud"] = []string{"https://other.example.com", sondaURL + "/admin"}
	})); err != nil {
		t.Errorf("array audience: %v", err)
	}
}

func TestVerifyReadsTheRolesClaim(t *testing.T) {
	client, server := newClient(t)
	cases := []struct {
		name  string
		roles any
		want  signin.Role
	}{
		{"no claim", nil, signin.RoleUnset},
		{"admin", []string{"sonda-admin"}, signin.RoleAdmin},
		{"viewer", []string{"sonda-viewer"}, signin.RoleViewer},
		{"admin wins over viewer", []string{"sonda-viewer", "sonda-admin"}, signin.RoleAdmin},
		{"only foreign roles", []string{"billing-admin"}, signin.RoleNone},
		{"an empty list", []string{}, signin.RoleNone},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			person, err := client.Verify(context.Background(), validToken(server, func(_, c map[string]any) {
				if tc.roles != nil {
					c["roles"] = tc.roles
				}
			}))
			if err != nil {
				t.Fatal(err)
			}
			if person.Role != tc.want {
				t.Errorf("role %q, want %q", person.Role, tc.want)
			}
		})
	}
}

func TestVerifyRefuses(t *testing.T) {
	client, server := newClient(t)
	cases := map[string]func(h, c map[string]any){
		"an ID token or other JWT":  func(h, _ map[string]any) { h["typ"] = "JWT" },
		"another algorithm":         func(h, _ map[string]any) { h["alg"] = "HS256" },
		"an unknown key":            func(h, _ map[string]any) { h["kid"] = "other" },
		"another issuer":            func(_, c map[string]any) { c["iss"] = "https://evil.example.com" },
		"another resource":          func(_, c map[string]any) { c["aud"] = "https://other.example.com/mcp" },
		"another client":            func(_, c map[string]any) { c["client_id"] = "https://claude.ai/oauth/client" },
		"an expired token":          func(_, c map[string]any) { c["exp"] = time.Now().Add(-time.Minute).Unix() },
		"no expiry":                 func(_, c map[string]any) { delete(c, "exp") },
		"no subject":                func(_, c map[string]any) { c["sub"] = "" },
		"a workload":                func(_, c map[string]any) { c["ptype"] = "job" },
		"no principal type":         func(_, c map[string]any) { delete(c, "ptype") },
		"roles that are no list":    func(_, c map[string]any) { c["roles"] = "sonda-admin" },
		"roles that are no strings": func(_, c map[string]any) { c["roles"] = []any{1} },
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := client.Verify(context.Background(), validToken(server, change)); err == nil {
				t.Error("accepted")
			}
		})
	}
	t.Run("a forged signature", func(t *testing.T) {
		token := validToken(server, nil)
		other := validToken(server, func(_, c map[string]any) { c["sub"] = "principal-2" })
		parts, otherParts := strings.Split(token, "."), strings.Split(other, ".")
		if _, err := client.Verify(context.Background(), parts[0]+"."+otherParts[1]+"."+parts[2]); err == nil {
			t.Error("accepted")
		}
	})
}

func TestExchange(t *testing.T) {
	client, server := newClient(t)
	server.SignIn("principal-1", "alice@example.com")
	noRedirects := server.Client()
	noRedirects.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }

	authorize := func(attempt signin.Attempt) (code, iss string) {
		t.Helper()
		target, err := client.AuthorizationURL(context.Background(), attempt)
		if err != nil {
			t.Fatal(err)
		}
		resp, err := noRedirects.Get(target)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		location, err := resp.Location()
		if err != nil {
			t.Fatal(err)
		}
		if !strings.HasPrefix(location.String(), sondaURL+"/admin/oauth/callback?") || location.Query().Get("state") != attempt.State {
			t.Fatalf("redirect to %s", location)
		}
		return location.Query().Get("code"), location.Query().Get("iss")
	}

	attempt := signin.NewAttempt()
	code, iss := authorize(attempt)
	person, err := client.Exchange(context.Background(), signin.Callback{Code: code, Issuer: iss}, attempt)
	if err != nil || person.Subject != "principal-1" {
		t.Fatalf("person %+v, err %v", person, err)
	}

	t.Run("refuses a wrong PKCE verifier", func(t *testing.T) {
		attempt := signin.NewAttempt()
		code, iss := authorize(attempt)
		if _, err := client.Exchange(context.Background(), signin.Callback{Code: code, Issuer: iss}, signin.NewAttempt()); err == nil {
			t.Error("accepted")
		}
	})
	t.Run("refuses a response from another issuer", func(t *testing.T) {
		attempt := signin.NewAttempt()
		code, _ := authorize(attempt)
		if _, err := client.Exchange(context.Background(), signin.Callback{Code: code, Issuer: "https://evil.example.com"}, attempt); err == nil {
			t.Error("accepted")
		}
	})
	t.Run("refuses a response without iss when the server sends it", func(t *testing.T) {
		attempt := signin.NewAttempt()
		code, _ := authorize(attempt)
		if _, err := client.Exchange(context.Background(), signin.Callback{Code: code}, attempt); err == nil {
			t.Error("accepted")
		}
	})
}

func TestMetadataMustNameTheConfiguredIssuer(t *testing.T) {
	server := signintest.New(t)
	client := signin.New(config.AdminOAuth{Issuer: server.URL + "/tenant", URL: sondaURL}, server.Client())
	if _, err := client.AuthorizationURL(context.Background(), signin.NewAttempt()); err == nil {
		t.Error("accepted metadata of another issuer")
	}
}

func TestClientMetadata(t *testing.T) {
	client, _ := newClient(t)
	meta := client.ClientMetadata()
	if meta.ClientID != sondaURL+"/admin/oauth/client" || len(meta.RedirectURIs) != 1 || meta.RedirectURIs[0] != sondaURL+"/admin/oauth/callback" ||
		meta.TokenEndpointAuthMethod != "none" || client.Resource() != sondaURL+"/admin" {
		t.Errorf("metadata %+v, resource %s", meta, client.Resource())
	}
}
