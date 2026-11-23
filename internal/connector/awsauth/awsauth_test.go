package awsauth

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	sdkaws "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"

	"github.com/contember/sonda/internal/config"
	"github.com/contember/sonda/internal/issuer"
)

type memoryKeys struct {
	keys []issuer.Key
}

func (m *memoryKeys) SigningKeys(context.Context) ([]issuer.Key, error) { return m.keys, nil }

func (m *memoryKeys) AddSigningKey(_ context.Context, key issuer.Key) error {
	m.keys = append(m.keys, key)
	return nil
}

func (m *memoryKeys) DeleteSigningKey(context.Context, string) error { return nil }

// isolateAWSEnvironment keeps the developer's AWS profile and credentials out of the test.
func isolateAWSEnvironment(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "missing")
	t.Setenv("AWS_CONFIG_FILE", missing)
	t.Setenv("AWS_SHARED_CREDENTIALS_FILE", missing)
	for _, name := range []string{"AWS_PROFILE", "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN", "AWS_ROLE_ARN", "AWS_WEB_IDENTITY_TOKEN_FILE"} {
		t.Setenv(name, "")
	}
}

func TestIdentityCredentialsAssumeRoleWithWebIdentity(t *testing.T) {
	isolateAWSEnvironment(t)
	var form url.Values
	sts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Error(err)
		}
		form = r.PostForm
		if r.Header.Get("Authorization") != "" {
			t.Error("AssumeRoleWithWebIdentity was signed with other credentials")
		}
		w.Header().Set("Content-Type", "text/xml")
		_, _ = w.Write([]byte(`<AssumeRoleWithWebIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
  <AssumeRoleWithWebIdentityResult>
    <Credentials>
      <AccessKeyId>ASIATEST</AccessKeyId>
      <SecretAccessKey>secret</SecretAccessKey>
      <SessionToken>session</SessionToken>
      <Expiration>2099-01-01T00:00:00Z</Expiration>
    </Credentials>
  </AssumeRoleWithWebIdentityResult>
</AssumeRoleWithWebIdentityResponse>`))
	}))
	defer sts.Close()
	t.Setenv("AWS_ENDPOINT_URL_STS", sts.URL)

	iss, err := issuer.Open(context.Background(), "https://sonda.example.com", &memoryKeys{})
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := Config(context.Background(), &config.AWSSource{
		Region:      "eu-west-1",
		Credentials: config.AWSIdentity,
		RoleARN:     "arn:aws:iam::123456789012:role/sonda",
	}, iss)
	if err != nil {
		t.Fatal(err)
	}
	creds, err := cfg.Credentials.Retrieve(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if creds.AccessKeyID != "ASIATEST" || creds.SessionToken != "session" {
		t.Errorf("credentials = %+v", creds)
	}
	if form.Get("Action") != "AssumeRoleWithWebIdentity" || form.Get("RoleArn") != "arn:aws:iam::123456789012:role/sonda" || form.Get("RoleSessionName") != "sonda" {
		t.Errorf("request = %v", form)
	}
	claims := jwtClaims(t, form.Get("WebIdentityToken"))
	if claims["iss"] != "https://sonda.example.com" || claims["aud"] != "sts.amazonaws.com" || claims["sub"] != "sonda" {
		t.Errorf("token claims = %v", claims)
	}
}

func TestIdentityCredentialsRequireIssuer(t *testing.T) {
	isolateAWSEnvironment(t)
	_, err := Config(context.Background(), &config.AWSSource{Region: "eu-west-1", Credentials: config.AWSIdentity, RoleARN: "arn:aws:iam::1:role/sonda"}, nil)
	if err == nil {
		t.Fatal("identity credentials without an issuer were accepted")
	}
}

func jwtClaims(t *testing.T, token string) map[string]any {
	t.Helper()
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("WebIdentityToken %q is not a JWT", token)
	}
	data, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	var claims map[string]any
	if err := json.Unmarshal(data, &claims); err != nil {
		t.Fatal(err)
	}
	return claims
}

func TestEKSToken(t *testing.T) {
	cfg := sdkaws.Config{
		Region:      "eu-west-1",
		Credentials: credentials.NewStaticCredentialsProvider("AKIDTEST", "secret", ""),
	}
	tokens := NewEKSTokens(cfg, "prod")
	now := time.Now()
	tokens.now = func() time.Time { return now }

	token, err := tokens.Token(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	presigned := presignedURL(t, token)
	query := presigned.Query()
	if presigned.Host != "sts.eu-west-1.amazonaws.com" || query.Get("Action") != "GetCallerIdentity" {
		t.Errorf("presigned URL = %s", presigned)
	}
	if query.Get("X-Amz-Expires") != "60" || !strings.HasPrefix(query.Get("X-Amz-Credential"), "AKIDTEST/") {
		t.Errorf("presigned URL = %s", presigned)
	}
	if !strings.Contains(query.Get("X-Amz-SignedHeaders"), "x-k8s-aws-id") {
		t.Errorf("signed headers %q do not include the cluster header", query.Get("X-Amz-SignedHeaders"))
	}

	again, err := tokens.Token(context.Background())
	if err != nil || again != token {
		t.Errorf("token within the reuse window was not reused: %v", err)
	}
	now = now.Add(eksTokenReuse)
	time.Sleep(time.Second) // X-Amz-Date has second precision
	renewed, err := tokens.Token(context.Background())
	if err != nil || renewed == token {
		t.Errorf("token after the reuse window was not renewed: %v", err)
	}
}

func presignedURL(t *testing.T, token string) *url.URL {
	t.Helper()
	encoded, ok := strings.CutPrefix(token, "k8s-aws-v1.")
	if !ok {
		t.Fatalf("token %q lacks the k8s-aws-v1. prefix", token)
	}
	raw, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatal(err)
	}
	presigned, err := url.Parse(string(raw))
	if err != nil {
		t.Fatal(err)
	}
	return presigned
}

// signingKey returns the access key ID a token was signed with.
func signingKey(t *testing.T, token string) string {
	t.Helper()
	key, _, _ := strings.Cut(presignedURL(t, token).Query().Get("X-Amz-Credential"), "/")
	return key
}

func TestEKSTokenNotReusedPastCredentialsExpiry(t *testing.T) {
	start := time.Now()
	now := start
	// The first credentials until they are near expiry, then new ones.
	provider := sdkaws.CredentialsProviderFunc(func(context.Context) (sdkaws.Credentials, error) {
		if now.Before(start.Add(5 * time.Minute)) {
			return sdkaws.Credentials{AccessKeyID: "AKIDFIRST", SecretAccessKey: "secret", CanExpire: true, Expires: start.Add(8 * time.Minute)}, nil
		}
		return sdkaws.Credentials{AccessKeyID: "AKIDSECOND", SecretAccessKey: "secret", CanExpire: true, Expires: start.Add(time.Hour)}, nil
	})
	tokens := NewEKSTokens(sdkaws.Config{Region: "eu-west-1", Credentials: provider}, "prod")
	tokens.now = func() time.Time { return now }

	first, err := tokens.Token(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if key := signingKey(t, first); key != "AKIDFIRST" {
		t.Fatalf("first token signed with %s", key)
	}
	now = start.Add(5 * time.Minute)
	if again, err := tokens.Token(context.Background()); err != nil || again != first {
		t.Errorf("token with valid credentials was not reused: %v", err)
	}
	// Within the reuse window, but past the expiry of the credentials minus the margin.
	now = start.Add(8*time.Minute - eksCredentialsMargin)
	renewed, err := tokens.Token(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if key := signingKey(t, renewed); key != "AKIDSECOND" {
		t.Errorf("token was reused or re-signed with %s after its credentials expired", key)
	}
}

// fakeSTS answers AssumeRole and AssumeRoleWithWebIdentity with new credentials on every call,
// each valid for validFor.
func fakeSTS(t *testing.T, validFor time.Duration) (*httptest.Server, *int) {
	t.Helper()
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Error(err)
		}
		calls++
		action := r.PostForm.Get("Action")
		w.Header().Set("Content-Type", "text/xml")
		_, _ = fmt.Fprintf(w, `<%[1]sResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
  <%[1]sResult>
    <Credentials>
      <AccessKeyId>ASIA%[2]d</AccessKeyId>
      <SecretAccessKey>secret</SecretAccessKey>
      <SessionToken>session</SessionToken>
      <Expiration>%[3]s</Expiration>
    </Credentials>
  </%[1]sResult>
</%[1]sResponse>`, action, calls, time.Now().Add(validFor).UTC().Format(time.RFC3339))
	}))
	t.Cleanup(server.Close)
	return server, &calls
}

func TestEKSTokenSignedWithCredentialsRefreshedBeforeExpiry(t *testing.T) {
	iss, err := issuer.Open(context.Background(), "https://sonda.example.com", &memoryKeys{})
	if err != nil {
		t.Fatal(err)
	}
	sourceKeys := func(t *testing.T) {
		t.Setenv("AWS_ACCESS_KEY_ID", "AKIDSOURCE")
		t.Setenv("AWS_SECRET_ACCESS_KEY", "secret")
	}
	for _, tc := range []struct {
		name     string
		settings *config.AWSSource
		env      func(t *testing.T)
	}{
		{"identity", &config.AWSSource{Region: "eu-west-1", Credentials: config.AWSIdentity, RoleARN: "arn:aws:iam::123456789012:role/sonda"}, sourceKeys},
		{"default with role", &config.AWSSource{Region: "eu-west-1", Credentials: config.AWSDefaultChain, RoleARN: "arn:aws:iam::123456789012:role/sonda"}, sourceKeys},
		// The default chain's own cache, here with web identity credentials from the environment.
		{"default chain", &config.AWSSource{Region: "eu-west-1", Credentials: config.AWSDefaultChain}, func(t *testing.T) {
			tokenFile := filepath.Join(t.TempDir(), "token")
			if err := os.WriteFile(tokenFile, []byte("web-identity-token"), 0o600); err != nil {
				t.Fatal(err)
			}
			t.Setenv("AWS_WEB_IDENTITY_TOKEN_FILE", tokenFile)
			t.Setenv("AWS_ROLE_ARN", "arn:aws:iam::123456789012:role/sonda")
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			isolateAWSEnvironment(t)
			tc.env(t)
			settings := tc.settings
			// Credentials that expire within the EKS token lifetime are near expiry.
			sts, calls := fakeSTS(t, 14*time.Minute)
			t.Setenv("AWS_ENDPOINT_URL_STS", sts.URL)
			cfg, err := Config(context.Background(), settings, iss)
			if err != nil {
				t.Fatal(err)
			}
			tokens := NewEKSTokens(cfg, "prod")

			first, err := tokens.Token(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			second, err := tokens.Token(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			if signingKey(t, first) != "ASIA1" || signingKey(t, second) != "ASIA2" || *calls != 2 {
				t.Errorf("tokens signed with %s, then %s after %d STS calls; want ASIA1, then refreshed ASIA2", signingKey(t, first), signingKey(t, second), *calls)
			}
		})
	}
}
