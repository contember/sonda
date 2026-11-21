package aws

import (
	"context"
	"errors"

	sdkaws "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/acm"
	acmtypes "github.com/aws/aws-sdk-go-v2/service/acm/types"

	"github.com/contember/sonda/internal/apierr"
	"github.com/contember/sonda/internal/authz"
)

// acmAPI is the part of the ACM client the connector uses. Only the description: never
// GetCertificate or ExportCertificate.
type acmAPI interface {
	DescribeCertificate(ctx context.Context, in *acm.DescribeCertificateInput, opts ...func(*acm.Options)) (*acm.DescribeCertificateOutput, error)
}

// Certificate describes a bound certificate. One that does not exist is a configuration error.
func (c *Client) Certificate(ctx context.Context, scope authz.ResourceScope, arn string) (acmtypes.CertificateDetail, error) {
	if !scope.HasCertificate(arn) {
		return acmtypes.CertificateDetail{}, c.outsideScope()
	}
	out, err := c.acm.DescribeCertificate(ctx, &acm.DescribeCertificateInput{CertificateArn: sdkaws.String(arn)})
	var notFound *acmtypes.ResourceNotFoundException
	if errors.As(err, &notFound) {
		return acmtypes.CertificateDetail{}, apierr.Upstream("source %s: certificate %s not found", c.source.Name, arn)
	}
	if err != nil {
		return acmtypes.CertificateDetail{}, c.apiError("DescribeCertificate", err)
	}
	if out.Certificate == nil {
		return acmtypes.CertificateDetail{}, apierr.Upstream("source %s: certificate %s not found", c.source.Name, arn)
	}
	if sdkaws.ToString(out.Certificate.CertificateArn) != arn {
		return acmtypes.CertificateDetail{}, c.outsideScope()
	}
	return *out.Certificate, nil
}
