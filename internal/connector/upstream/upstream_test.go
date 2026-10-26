package upstream

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/contember/sonda/internal/config"
)

func TestCredentialsStayOnSourceOrigin(t *testing.T) {
	type seen struct{ auth, header string }
	var foreign, own []seen
	foreignServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		foreign = append(foreign, seen{r.Header.Get("Authorization"), r.Header.Get("X-Secret")})
	}))
	defer foreignServer.Close()
	ownServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		own = append(own, seen{r.Header.Get("Authorization"), r.Header.Get("X-Secret")})
		switch r.URL.Path {
		case "/same":
			http.Redirect(w, r, "/target", http.StatusFound)
		case "/away":
			http.Redirect(w, r, foreignServer.URL+"/target", http.StatusFound)
		}
	}))
	defer ownServer.Close()

	client := HTTPClient(&config.Source{
		Name:    "test",
		URL:     ownServer.URL,
		Auth:    config.Auth{Type: config.AuthBearer, Token: "secret-token"},
		Headers: map[string]string{"X-Secret": "secret-header"},
	})
	for _, path := range []string{"/same", "/away"} {
		resp, err := client.Get(ownServer.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
	}

	want := seen{"Bearer secret-token", "secret-header"}
	if len(own) != 3 {
		t.Fatalf("own origin got %d requests, want 3", len(own))
	}
	for i, s := range own {
		if s != want {
			t.Errorf("own origin request %d got %+v, want %+v", i, s, want)
		}
	}
	if len(foreign) != 1 {
		t.Fatalf("foreign origin got %d requests, want 1", len(foreign))
	}
	if foreign[0] != (seen{}) {
		t.Errorf("foreign origin got credentials %+v", foreign[0])
	}
}
