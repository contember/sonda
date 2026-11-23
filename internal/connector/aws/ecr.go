package aws

import (
	"context"
	"encoding/json"
	"errors"
	"regexp"
	"slices"
	"strings"

	sdkaws "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ecr"
	ecrtypes "github.com/aws/aws-sdk-go-v2/service/ecr/types"

	"github.com/contember/sonda/internal/apierr"
	"github.com/contember/sonda/internal/authz"
)

// ecrAPI is the part of the ECR client the connector uses.
type ecrAPI interface {
	DescribeImages(ctx context.Context, in *ecr.DescribeImagesInput, opts ...func(*ecr.Options)) (*ecr.DescribeImagesOutput, error)
	DescribeImageScanFindings(ctx context.Context, in *ecr.DescribeImageScanFindingsInput, opts ...func(*ecr.Options)) (*ecr.DescribeImageScanFindingsOutput, error)
	BatchGetImage(ctx context.Context, in *ecr.BatchGetImageInput, opts ...func(*ecr.Options)) (*ecr.BatchGetImageOutput, error)
}

const (
	// ecrPage is the most results DescribeImages and DescribeImageScanFindings return per call.
	ecrPage = 1000
	// maxRepositoryImages stops reading a repository; DescribeImages has no order, so the
	// caller can find the newest images only among those read.
	maxRepositoryImages = 5000
	// maxScanFindings stops reading the findings of one scan.
	maxScanFindings = 5000
	// maxPlatformManifests stops reading the image manifests of one index.
	maxPlatformManifests = 16
)

var (
	// indexMediaTypes list other manifests instead of layers; the registry scans the listed ones.
	indexMediaTypes = []string{"application/vnd.oci.image.index.v1+json", "application/vnd.docker.distribution.manifest.list.v2+json"}
	// imageMediaTypes are the manifests of one image, which the registry scans.
	imageMediaTypes = []string{"application/vnd.oci.image.manifest.v1+json", "application/vnd.docker.distribution.manifest.v2+json"}
	digestFormat    = regexp.MustCompile(`^sha256:[a-f0-9]{64}$`)
	// platformPart bounds the os, architecture and variant the pusher wrote, e.g. linux, arm64, v8.
	platformPart = regexp.MustCompile(`^[a-z0-9._-]{1,32}$`)
)

// PlatformManifest is the image manifest an index lists for one platform.
type PlatformManifest struct {
	Digest string
	// Platform is os/architecture[/variant] as the index states it, e.g. linux/arm64; empty
	// when the index states none or a part is not a plain lowercase name.
	Platform string
}

// IsIndex reports whether image is an index (a multi-platform image, or one pushed with
// attestations), which has no scan of its own.
func IsIndex(image ecrtypes.ImageDetail) bool {
	return slices.Contains(indexMediaTypes, sdkaws.ToString(image.ImageManifestMediaType))
}

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

// PlatformManifests reads the index with digest and returns the image manifests it lists, up
// to maxPlatformManifests, and whether more exist. Attestation manifests (buildx provenance and
// SBOM) and nested indexes are left out: they are not images the registry scans.
func (c *Client) PlatformManifests(ctx context.Context, scope authz.ImageScope, repository, digest string) ([]PlatformManifest, bool, error) {
	if !scope.Has(repository) {
		return nil, false, c.outsideScope()
	}
	out, err := c.ecr.BatchGetImage(ctx, &ecr.BatchGetImageInput{
		RepositoryName:     sdkaws.String(repository),
		ImageIds:           []ecrtypes.ImageIdentifier{{ImageDigest: sdkaws.String(digest)}},
		AcceptedMediaTypes: indexMediaTypes,
	})
	if err != nil {
		return nil, false, c.apiError("BatchGetImage", err)
	}
	if len(out.Failures) > 0 {
		failure := out.Failures[0]
		if failure.FailureCode == ecrtypes.ImageFailureCodeImageNotFound {
			return nil, false, nil
		}
		return nil, false, apierr.Upstream("source %s: BatchGetImage failed: %s", c.source.Name, failure.FailureCode)
	}
	if len(out.Images) != 1 {
		return nil, false, apierr.Upstream("source %s: BatchGetImage returned %d manifests for one digest", c.source.Name, len(out.Images))
	}
	image := out.Images[0]
	if sdkaws.ToString(image.RepositoryName) != repository || image.ImageId == nil || sdkaws.ToString(image.ImageId.ImageDigest) != digest {
		return nil, false, c.outsideScope()
	}
	return c.parseIndex(sdkaws.ToString(image.ImageManifest))
}

// parseIndex reads the image manifests of an index manifest, which the image's pusher wrote.
func (c *Client) parseIndex(manifest string) ([]PlatformManifest, bool, error) {
	var index struct {
		Manifests []struct {
			MediaType string `json:"mediaType"`
			Digest    string `json:"digest"`
			Platform  struct {
				OS           string `json:"os"`
				Architecture string `json:"architecture"`
				Variant      string `json:"variant"`
			} `json:"platform"`
			Annotations map[string]string `json:"annotations"`
		} `json:"manifests"`
	}
	if err := json.Unmarshal([]byte(manifest), &index); err != nil {
		return nil, false, apierr.Upstream("source %s: the index manifest is not valid JSON", c.source.Name)
	}
	result := []PlatformManifest{}
	for _, m := range index.Manifests {
		if !slices.Contains(imageMediaTypes, m.MediaType) || m.Annotations["vnd.docker.reference.type"] == "attestation-manifest" {
			continue
		}
		if !digestFormat.MatchString(m.Digest) {
			return nil, false, apierr.Upstream("source %s: the index lists a manifest with an invalid digest", c.source.Name)
		}
		if len(result) == maxPlatformManifests {
			return result, true, nil
		}
		result = append(result, PlatformManifest{Digest: m.Digest, Platform: platformName(m.Platform.OS, m.Platform.Architecture, m.Platform.Variant)})
	}
	return result, false, nil
}

// platformName joins os/architecture[/variant], or returns "" when os or architecture is missing
// or any part is not a plain lowercase name.
func platformName(os, architecture, variant string) string {
	parts := []string{os, architecture}
	if variant != "" {
		parts = append(parts, variant)
	}
	for _, part := range parts {
		if !platformPart.MatchString(part) {
			return ""
		}
	}
	return strings.Join(parts, "/")
}

// Scan reads the status and the counts per severity of the latest scan of the image, without its
// findings. An image that was never scanned returns nil.
func (c *Client) Scan(ctx context.Context, scope authz.ImageScope, repository, digest string) (*ecr.DescribeImageScanFindingsOutput, error) {
	if !scope.Has(repository) {
		return nil, c.outsideScope()
	}
	return c.scanPage(ctx, repository, digest, 1, nil)
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
		out, err := c.scanPage(ctx, repository, digest, ecrPage, next)
		if err != nil || out == nil {
			return nil, false, err
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

// scanPage reads one page of the findings of the latest scan of the image, or nil when it was
// never scanned.
func (c *Client) scanPage(ctx context.Context, repository, digest string, size int32, next *string) (*ecr.DescribeImageScanFindingsOutput, error) {
	out, err := c.ecr.DescribeImageScanFindings(ctx, &ecr.DescribeImageScanFindingsInput{
		RepositoryName: sdkaws.String(repository),
		ImageId:        &ecrtypes.ImageIdentifier{ImageDigest: sdkaws.String(digest)},
		MaxResults:     sdkaws.Int32(size),
		NextToken:      next,
	})
	var noScan *ecrtypes.ScanNotFoundException
	if errors.As(err, &noScan) {
		return nil, nil
	}
	if err != nil {
		return nil, c.apiError("DescribeImageScanFindings", err)
	}
	if sdkaws.ToString(out.RepositoryName) != repository || out.ImageId == nil || sdkaws.ToString(out.ImageId.ImageDigest) != digest {
		return nil, c.outsideScope()
	}
	return out, nil
}
