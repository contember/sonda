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
)

// Config loads the configuration of an aws source. Credentials are resolved on the first
// request, so Config does not call AWS.
func Config(ctx context.Context, settings *config.AWSSource, identity *issuer.Issuer) (sdkaws.Config, error) {
	cfg, err := awsconfig.LoadDefaultConfig(ctx, awsconfig.WithRegion(settings.Region))
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
		cfg.Credentials = sdkaws.NewCredentialsCache(provider)
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
		cfg.Credentials = sdkaws.NewCredentialsCache(provider)
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
)

// EKSTokens returns bearer tokens for the Kubernetes API of an EKS cluster: a presigned STS
// GetCallerIdentity request that names the cluster, as aws eks get-token creates.
type EKSTokens struct {
	presign *sts.PresignClient
	cluster string
	now     func() time.Time

	mu       sync.Mutex
	token    string
	signedAt time.Time
}

func NewEKSTokens(cfg sdkaws.Config, cluster string) *EKSTokens {
	return &EKSTokens{presign: sts.NewPresignClient(sts.NewFromConfig(cfg)), cluster: cluster, now: time.Now}
}

func (t *EKSTokens) Token(ctx context.Context) (string, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	now := t.now()
	if t.token != "" && now.Sub(t.signedAt) < eksTokenReuse {
		return t.token, nil
	}
	req, err := t.presign.PresignGetCallerIdentity(ctx, &sts.GetCallerIdentityInput{}, func(o *sts.PresignOptions) {
		o.ClientOptions = append(o.ClientOptions, sts.WithAPIOptions(
			smithyhttp.SetHeaderValue(clusterIDHeader, t.cluster),
			smithyhttp.SetHeaderValue("X-Amz-Expires", "60"),
		))
	})
	if err != nil {
		return "", err
	}
	t.token = eksTokenPrefix + base64.RawURLEncoding.EncodeToString([]byte(req.URL))
	t.signedAt = now
	return t.token, nil
}
