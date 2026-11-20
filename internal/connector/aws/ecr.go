package aws

import (
	"context"
	"errors"

	sdkaws "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ecr"
	ecrtypes "github.com/aws/aws-sdk-go-v2/service/ecr/types"

	"github.com/contember/sonda/internal/authz"
)

// ecrAPI is the part of the ECR client the connector uses.
type ecrAPI interface {
	DescribeImages(ctx context.Context, in *ecr.DescribeImagesInput, opts ...func(*ecr.Options)) (*ecr.DescribeImagesOutput, error)
	DescribeImageScanFindings(ctx context.Context, in *ecr.DescribeImageScanFindingsInput, opts ...func(*ecr.Options)) (*ecr.DescribeImageScanFindingsOutput, error)
}

const (
	// ecrPage is the most results DescribeImages and DescribeImageScanFindings return per call.
	ecrPage = 1000
	// maxRepositoryImages stops reading a repository; DescribeImages has no order, so the
	// caller can find the newest images only among those read.
	maxRepositoryImages = 5000
	// maxScanFindings stops reading the findings of one scan.
	maxScanFindings = 5000
)

// Image returns the image with digest in repository, or false when the repository has none.
func (c *Client) Image(ctx context.Context, scope authz.ImageScope, repository, digest string) (ecrtypes.ImageDetail, bool, error) {
	if !scope.Has(repository) {
		return ecrtypes.ImageDetail{}, false, c.outsideScope()
	}
	out, err := c.ecr.DescribeImages(ctx, &ecr.DescribeImagesInput{
		RepositoryName: sdkaws.String(repository),
		ImageIds:       []ecrtypes.ImageIdentifier{{ImageDigest: sdkaws.String(digest)}},
	})
	var notFound *ecrtypes.ImageNotFoundException
	if errors.As(err, &notFound) {
		return ecrtypes.ImageDetail{}, false, nil
	}
	if err != nil {
		return ecrtypes.ImageDetail{}, false, c.apiError("DescribeImages", err)
	}
	for _, image := range out.ImageDetails {
		if sdkaws.ToString(image.RepositoryName) != repository || sdkaws.ToString(image.ImageDigest) != digest {
			return ecrtypes.ImageDetail{}, false, c.outsideScope()
		}
	}
	if len(out.ImageDetails) == 0 {
		return ecrtypes.ImageDetail{}, false, nil
	}
	return out.ImageDetails[0], true, nil
}

// Images reads up to maxRepositoryImages images of repository, in no particular order, and
// reports whether more exist.
func (c *Client) Images(ctx context.Context, scope authz.ImageScope, repository string) ([]ecrtypes.ImageDetail, bool, error) {
	if !scope.Has(repository) {
		return nil, false, c.outsideScope()
	}
	var (
		images []ecrtypes.ImageDetail
		next   *string
	)
	for {
		out, err := c.ecr.DescribeImages(ctx, &ecr.DescribeImagesInput{
			RepositoryName: sdkaws.String(repository),
			MaxResults:     sdkaws.Int32(ecrPage),
			NextToken:      next,
		})
		if err != nil {
			return nil, false, c.apiError("DescribeImages", err)
		}
		for _, image := range out.ImageDetails {
			if sdkaws.ToString(image.RepositoryName) != repository {
				return nil, false, c.outsideScope()
			}
		}
		images = append(images, out.ImageDetails...)
		if len(images) >= maxRepositoryImages {
			return images[:maxRepositoryImages], len(images) > maxRepositoryImages || out.NextToken != nil, nil
		}
		if out.NextToken == nil {
			return images, false, nil
		}
		next = out.NextToken
	}
}

// ScanFindings reads the findings of the latest scan of the image, up to maxScanFindings, and
// reports whether more exist. A basic scan fills Findings, an enhanced scan EnhancedFindings.
// An image that was never scanned returns nil.
func (c *Client) ScanFindings(ctx context.Context, scope authz.ImageScope, repository, digest string) (*ecr.DescribeImageScanFindingsOutput, bool, error) {
	if !scope.Has(repository) {
		return nil, false, c.outsideScope()
	}
	var (
		result *ecr.DescribeImageScanFindingsOutput
		next   *string
		count  int
	)
	for {
		out, err := c.ecr.DescribeImageScanFindings(ctx, &ecr.DescribeImageScanFindingsInput{
			RepositoryName: sdkaws.String(repository),
			ImageId:        &ecrtypes.ImageIdentifier{ImageDigest: sdkaws.String(digest)},
			MaxResults:     sdkaws.Int32(ecrPage),
			NextToken:      next,
		})
		var noScan *ecrtypes.ScanNotFoundException
		if errors.As(err, &noScan) {
			return nil, false, nil
		}
		if err != nil {
			return nil, false, c.apiError("DescribeImageScanFindings", err)
		}
		if sdkaws.ToString(out.RepositoryName) != repository || out.ImageId == nil || sdkaws.ToString(out.ImageId.ImageDigest) != digest {
			return nil, false, c.outsideScope()
		}
		if result == nil {
			result = out
			if result.ImageScanFindings == nil {
				result.ImageScanFindings = &ecrtypes.ImageScanFindings{}
			}
		} else if out.ImageScanFindings != nil {
			result.ImageScanFindings.Findings = append(result.ImageScanFindings.Findings, out.ImageScanFindings.Findings...)
			result.ImageScanFindings.EnhancedFindings = append(result.ImageScanFindings.EnhancedFindings, out.ImageScanFindings.EnhancedFindings...)
		}
		count = len(result.ImageScanFindings.Findings) + len(result.ImageScanFindings.EnhancedFindings)
		if count >= maxScanFindings {
			return result, out.NextToken != nil || count > maxScanFindings, nil
		}
		if out.NextToken == nil {
			return result, false, nil
		}
		next = out.NextToken
	}
}
