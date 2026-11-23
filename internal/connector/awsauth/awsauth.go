// Package awsauth resolves the AWS configuration of aws sources. The CloudWatch connector uses
// it, and so do sources that authenticate to EKS with the credentials of an aws source.
package awsauth

import (
	"context"
	"encoding/base64"
	"errors"
	"sync"
	"time"

	sdkaws "github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	smithyhttp "github.com/aws/smithy-go/transport/http"

	"github.com/contember/sonda/internal/config"
	"github.com/contember/sonda/internal/issuer"
)

const (
	roleSessionName = "sonda"
	stsAudience     = "sts.amazonaws.com"
	// Credentials are refreshed this long before they expire, so an EKS token signed with
	// them stays valid for its whole lifetime (15 minutes).
	credentialsExpiryWindow = 15 * time.Minute
)

func setExpiryWindow(o *sdkaws.CredentialsCacheOptions) {
	o.ExpiryWindow = credentialsExpiryWindow
}

// Config loads the configuration of an aws source. Credentials are resolved on the first
// request, so Config does not call AWS.
func Config(ctx context.Context, settings *config.AWSSource, identity *issuer.Issuer) (sdkaws.Config, error) {
	cfg, err := awsconfig.LoadDefaultConfig(ctx, awsconfig.WithRegion(settings.Region), awsconfig.WithCredentialsCacheOptions(setExpiryWindow))
	if err != nil {
		return sdkaws.Config{}, err
	}
	switch settings.Credentials {
	case config.AWSIdentity:
		if identity == nil {
			return sdkaws.Config{}, errors.New("credentials: identity requires Sonda's identity")
		}
		// AssumeRoleWithWebIdentity is unsigned, so the default chain is never consulted.
		provider := stscreds.NewWebIdentityRoleProvider(sts.NewFromConfig(cfg), settings.RoleARN, identityToken{identity}, func(o *stscreds.WebIdentityRoleOptions) {
			o.RoleSessionName = roleSessionName
		})
		cfg.Credentials = sdkaws.NewCredentialsCache(provider, setExpiryWindow)
	case config.AWSDefaultChain:
		if settings.RoleARN == "" {
			return cfg, nil
		}
		provider := stscreds.NewAssumeRoleProvider(sts.NewFromConfig(cfg), settings.RoleARN, func(o *stscreds.AssumeRoleOptions) {
			o.RoleSessionName = roleSessionName
			if settings.ExternalID != "" {
				o.ExternalID = sdkaws.String(settings.ExternalID)
			}
		})
		cfg.Credentials = sdkaws.NewCredentialsCache(provider, setExpiryWindow)
	}
	return cfg, nil
}

type identityToken struct {
	issuer *issuer.Issuer
}

func (t identityToken) GetIdentityToken() ([]byte, error) {
	token, err := t.issuer.Token(stsAudience)
	return []byte(token), err
}

const (
	clusterIDHeader = "x-k8s-aws-id"
	eksTokenPrefix  = "k8s-aws-v1."
	// EKS accepts a token for 15 minutes after it was signed and ignores X-Amz-Expires, which
	// it still requires; reusing it for 10 minutes leaves room for clock skew.
	eksTokenReuse = 10 * time.Minute
	// EKS rejects a token once the credentials it was signed with expire, so a token is not
	// reused past their expiry minus this margin for clock skew and latency.
	eksCredentialsMargin = time.Minute
)

// EKSTokens returns bearer tokens for the Kubernetes API of an EKS cluster: a presigned STS
// GetCallerIdentity request that names the cluster, as aws eks get-token creates.
type EKSTokens struct {
	presign     *sts.PresignClient
	credentials sdkaws.CredentialsProvider
	cluster     string
	now         func() time.Time

	mu         sync.Mutex
	token      string
	reuseUntil time.Time
}

func NewEKSTokens(cfg sdkaws.Config, cluster string) *EKSTokens {
	return &EKSTokens{presign: sts.NewPresignClient(sts.NewFromConfig(cfg)), credentials: cfg.Credentials, cluster: cluster, now: time.Now}
}

func (t *EKSTokens) Token(ctx context.Context) (string, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	now := t.now()
	if t.token != "" && now.Before(t.reuseUntil) {
		return t.token, nil
	}
	// Signing with the retrieved credentials, not the provider, ties the token to the expiry read here.
	creds, err := t.credentials.Retrieve(ctx)
	if err != nil {
		return "", err
	}
	req, err := t.presign.PresignGetCallerIdentity(ctx, &sts.GetCallerIdentityInput{}, func(o *sts.PresignOptions) {
		o.ClientOptions = append(o.ClientOptions, func(o *sts.Options) {
			o.Credentials = sdkaws.CredentialsProviderFunc(func(context.Context) (sdkaws.Credentials, error) {
				return creds, nil
			})
		}, sts.WithAPIOptions(
			smithyhttp.SetHeaderValue(clusterIDHeader, t.cluster),
			smithyhttp.SetHeaderValue("X-Amz-Expires", "60"),
		))
	})
	if err != nil {
		return "", err
	}
	t.token = eksTokenPrefix + base64.RawURLEncoding.EncodeToString([]byte(req.URL))
	t.reuseUntil = now.Add(eksTokenReuse)
	if expiry := creds.Expires.Add(-eksCredentialsMargin); creds.CanExpire && expiry.Before(t.reuseUntil) {
		t.reuseUntil = expiry
	}
	return t.token, nil
}
