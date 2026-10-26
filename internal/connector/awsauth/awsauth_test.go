package awsauth

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
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
