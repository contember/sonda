// Package aws queries CloudWatch Logs Insights and CloudWatch Metrics.
package aws

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	sdkaws "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/retry"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/aws/smithy-go"

	"github.com/contember/sonda/internal/apierr"
	"github.com/contember/sonda/internal/config"
)

const roleSessionName = "sonda"

// logsAPI is the part of the CloudWatch Logs client the connector uses.
type logsAPI interface {
	StartQuery(ctx context.Context, in *cloudwatchlogs.StartQueryInput, opts ...func(*cloudwatchlogs.Options)) (*cloudwatchlogs.StartQueryOutput, error)
	GetQueryResults(ctx context.Context, in *cloudwatchlogs.GetQueryResultsInput, opts ...func(*cloudwatchlogs.Options)) (*cloudwatchlogs.GetQueryResultsOutput, error)
	StopQuery(ctx context.Context, in *cloudwatchlogs.StopQueryInput, opts ...func(*cloudwatchlogs.Options)) (*cloudwatchlogs.StopQueryOutput, error)
	ListLogGroupsForQuery(ctx context.Context, in *cloudwatchlogs.ListLogGroupsForQueryInput, opts ...func(*cloudwatchlogs.Options)) (*cloudwatchlogs.ListLogGroupsForQueryOutput, error)
	GetLogGroupFields(ctx context.Context, in *cloudwatchlogs.GetLogGroupFieldsInput, opts ...func(*cloudwatchlogs.Options)) (*cloudwatchlogs.GetLogGroupFieldsOutput, error)
}

// identityAPI resolves the account of Sonda's credentials.
type identityAPI interface {
	GetCallerIdentity(ctx context.Context, in *sts.GetCallerIdentityInput, opts ...func(*sts.Options)) (*sts.GetCallerIdentityOutput, error)
}

// metricsAPI is the part of the CloudWatch client the connector uses.
type metricsAPI interface {
	GetMetricData(ctx context.Context, in *cloudwatch.GetMetricDataInput, opts ...func(*cloudwatch.Options)) (*cloudwatch.GetMetricDataOutput, error)
	ListMetrics(ctx context.Context, in *cloudwatch.ListMetricsInput, opts ...func(*cloudwatch.Options)) (*cloudwatch.ListMetricsOutput, error)
}

type Client struct {
	source   *config.Source
	logs     logsAPI
	metrics  metricsAPI
	identity identityAPI
	// accountMu guards accountID, the account of Sonda's credentials once resolved.
	accountMu sync.Mutex
	accountID string
	// firstPoll and maxPoll bound the backoff between GetQueryResults calls.
	firstPoll time.Duration
	maxPoll   time.Duration
}

// New loads the AWS configuration once. Credentials are resolved on the first request, so New
// does not call AWS.
func New(src *config.Source) (*Client, error) {
	if src.AWS == nil {
		return nil, fmt.Errorf("source %s has no AWS settings", src.Name)
	}
	cfg, err := loadConfig(context.Background(), src.AWS)
	if err != nil {
		return nil, fmt.Errorf("source %s: load AWS configuration: %w", src.Name, err)
	}
	return newClient(src, cloudwatchlogs.NewFromConfig(cfg), cloudwatch.NewFromConfig(cfg), sts.NewFromConfig(cfg)), nil
}

func newClient(src *config.Source, logs logsAPI, metrics metricsAPI, identity identityAPI) *Client {
	return &Client{
		source:    src,
		logs:      logs,
		metrics:   metrics,
		identity:  identity,
		firstPoll: 250 * time.Millisecond,
		maxPoll:   2 * time.Second,
	}
}

// loadConfig uses the default credential chain, and assumes the role on top of it when set.
func loadConfig(ctx context.Context, settings *config.AWSSource) (sdkaws.Config, error) {
	cfg, err := awsconfig.LoadDefaultConfig(ctx, awsconfig.WithRegion(settings.Region))
	if err != nil {
		return sdkaws.Config{}, err
	}
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
	return cfg, nil
}

var authErrorCodes = map[string]bool{
	"AccessDenied":                true,
	"AccessDeniedException":       true,
	"UnauthorizedOperation":       true,
	"NotAuthorized":               true,
	"UnrecognizedClientException": true,
	"InvalidClientTokenId":        true,
	"ExpiredToken":                true,
	"ExpiredTokenException":       true,
	"InvalidSignatureException":   true,
	"SignatureDoesNotMatch":       true,
	"IncompleteSignature":         true,
	"MissingAuthenticationToken":  true,
}

// apiError converts an SDK error into an error safe to show. Messages of auth failures name
// principals, and messages of credential providers can echo credentials, so neither is shown;
// the latter stay plain errors, which the HTTP layer logs and reports as internal.
func (c *Client) apiError(operation string, err error) error {
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return err
	}
	var apiErr smithy.APIError
	if !errors.As(err, &apiErr) {
		var netErr net.Error
		if errors.As(err, &netErr) {
			return apierr.Upstream("source %s is unreachable: %v", c.source.Name, netErr)
		}
		return fmt.Errorf("source %s: %s: %w", c.source.Name, operation, err)
	}
	code := apiErr.ErrorCode()
	_, throttled := retry.DefaultThrottleErrorCodes[code]
	switch {
	case code == "MalformedQueryException":
		return apierr.InvalidQuery("invalid Logs Insights query: %s", apiErr.ErrorMessage())
	case authErrorCodes[code]:
		return apierr.Upstream("source %s: AWS denied %s (%s); check the permissions of Sonda's AWS credentials", c.source.Name, operation, code)
	case throttled || code == "LimitExceededException":
		return apierr.Upstream("source %s: AWS throttled %s (%s); retry later", c.source.Name, operation, code)
	}
	return apierr.Upstream("source %s: %s failed: %s: %s", c.source.Name, operation, code, apiErr.ErrorMessage())
}
