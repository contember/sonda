package query

import (
	"context"
	"fmt"
	"net/url"
	"regexp"
	"slices"
	"sort"
	"strings"

	sdkaws "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ecr"
	ecrtypes "github.com/aws/aws-sdk-go-v2/service/ecr/types"

	"github.com/contember/sonda/api"
	"github.com/contember/sonda/internal/apierr"
	"github.com/contember/sonda/internal/authz"
)

const (
	defaultImages   = 20
	maxImages       = 100
	defaultFindings = 100
	maxFindings     = 1000
	// maxImageLookups bounds the DescribeImages calls of one digest lookup (repositories × digests).
	maxImageLookups = 50
)

var (
	imageDigestFormat = regexp.MustCompile(`^sha256:[a-f0-9]{64}$`)
	imagesUntrusted   = []string{"data[].tags", "data[].scan.description"}
	imageUntrusted    = []string{"data.tags", "data.scan.description"}
)

// Images returns the images of the service's repositories with their scan summaries: those with
// the requested digests, or the newest pushed.
func (s *Service) Images(ctx context.Context, identity *authz.Identity, service string, req api.ImagesRequest) (api.Response[[]api.Image], error) {
	scope, err := s.authz.ImageScope(identity, service, req.Environment)
	if err != nil {
		return api.Response[[]api.Image]{}, err
	}
	repositories, err := imageRepositories(scope, req.Repository)
	if err != nil {
		return api.Response[[]api.Image]{}, err
	}
	for _, digest := range req.Digests {
		if !imageDigestFormat.MatchString(digest) {
			return api.Response[[]api.Image]{}, apierr.InvalidRequest("digest %q must be sha256: followed by 64 lowercase hex characters", digest)
		}
	}
	if lookups := len(repositories) * len(req.Digests); lookups > maxImageLookups {
		return api.Response[[]api.Image]{}, apierr.InvalidRequest("%d digests in %d repositories need %d lookups, more than %d; pass fewer digests or a repository", len(req.Digests), len(repositories), lookups, maxImageLookups)
	}
	limit, err := boundedLimit(req.Limit, defaultImages, maxImages)
	if err != nil {
		return api.Response[[]api.Image]{}, err
	}

	client := s.connectors.AWS[scope.Source().Name]
	var (
		images    []ecrtypes.ImageDetail
		truncated bool
		sources   []api.SourceRef
	)
	for _, repo := range repositories {
		var query string
		if len(req.Digests) > 0 {
			query = fmt.Sprintf("repository=%s digests=%s", repo, strings.Join(req.Digests, ","))
			recordQuery(ctx, scope.Target, query)
			for _, digest := range req.Digests {
				image, found, err := client.Image(ctx, scope, repo, digest)
				if err != nil {
					return api.Response[[]api.Image]{}, err
				}
				if found {
					images = append(images, image)
				}
			}
		} else {
			query = "repository=" + repo + " newest"
			recordQuery(ctx, scope.Target, query)
			found, cut, err := client.Images(ctx, scope, repo)
			if err != nil {
				return api.Response[[]api.Image]{}, err
			}
			images = append(images, found...)
			truncated = truncated || cut
		}
		sources = append(sources, ecrSourceRef(scope, repo, query, images))
	}
	sort.SliceStable(images, func(i, j int) bool {
		return sdkaws.ToTime(images[i].ImagePushedAt).After(sdkaws.ToTime(images[j].ImagePushedAt))
	})
	result := make([]api.Image, 0, min(len(images), limit))
	for _, image := range images[:min(len(images), limit)] {
		result = append(result, shapeImage(image))
	}
	return api.Response[[]api.Image]{
		Data: result,
		Meta: api.Meta{
			Service:     service,
			Environment: scope.Environment(),
			Sources:     sources,
			Untrusted:   imagesUntrusted,
			Truncated:   truncated || len(images) > limit,
		},
	}, nil
}

// Image returns one image of the service's repositories with the findings of its latest scan,
// most severe first.
func (s *Service) Image(ctx context.Context, identity *authz.Identity, service, digest string, req api.ImagesRequest) (api.Response[api.ImageDetail], error) {
	scope, err := s.authz.ImageScope(identity, service, req.Environment)
	if err != nil {
		return api.Response[api.ImageDetail]{}, err
	}
	repositories, err := imageRepositories(scope, req.Repository)
	if err != nil {
		return api.Response[api.ImageDetail]{}, err
	}
	if !imageDigestFormat.MatchString(digest) {
		return api.Response[api.ImageDetail]{}, apierr.InvalidRequest("digest %q must be sha256: followed by 64 lowercase hex characters", digest)
	}
	limit, err := boundedLimit(req.Limit, defaultFindings, maxFindings)
	if err != nil {
		return api.Response[api.ImageDetail]{}, err
	}

	client := s.connectors.AWS[scope.Source().Name]
	for _, repo := range repositories {
		query := fmt.Sprintf("repository=%s digest=%s", repo, digest)
		recordQuery(ctx, scope.Target, query)
		image, found, err := client.Image(ctx, scope, repo, digest)
		if err != nil {
			return api.Response[api.ImageDetail]{}, err
		}
		if !found {
			continue
		}
		scan, cut, err := client.ScanFindings(ctx, scope, repo, digest)
		if err != nil {
			return api.Response[api.ImageDetail]{}, err
		}
		findings := shapeFindings(scan)
		detail := api.ImageDetail{Image: shapeImage(image), Findings: findings[:min(len(findings), limit)]}
		return api.Response[api.ImageDetail]{
			Data: detail,
			Meta: api.Meta{
				Service:     service,
				Environment: scope.Environment(),
				Sources:     []api.SourceRef{ecrSourceRef(scope, repo, query, []ecrtypes.ImageDetail{image})},
				Untrusted:   imageUntrusted,
				Truncated:   cut || len(findings) > limit,
			},
		}, nil
	}
	return api.Response[api.ImageDetail]{}, apierr.NotFound("image %s is not in the repositories of %s/%s", digest, service, scope.Environment())
}

// imageRepositories returns the requested repository, which must be bound, or all bound ones.
func imageRepositories(scope authz.ImageScope, repository string) ([]string, error) {
	if repository == "" {
		return scope.Repositories(), nil
	}
	if !scope.Has(repository) {
		return nil, apierr.NotFound("repository %q is not bound to %s/%s", repository, scope.Service(), scope.Environment())
	}
	return []string{repository}, nil
}

func boundedLimit(limit, fallback, maximum int) (int, error) {
	switch {
	case limit == 0:
		return fallback, nil
	case limit < 0 || limit > maximum:
		return 0, apierr.InvalidRequest("limit must be between 1 and %d", maximum)
	}
	return limit, nil
}

func shapeImage(image ecrtypes.ImageDetail) api.Image {
	tags := slices.Clone(image.ImageTags)
	if tags == nil {
		tags = []string{}
	}
	slices.Sort(tags)
	result := api.Image{
		Repository: sdkaws.ToString(image.RepositoryName),
		Digest:     sdkaws.ToString(image.ImageDigest),
		Tags:       tags,
		PushedAt:   image.ImagePushedAt,
		SizeBytes:  sdkaws.ToInt64(image.ImageSizeInBytes),
		LastPulled: image.LastRecordedPullTime,
	}
	if status := image.ImageScanStatus; status != nil {
		result.Scan = &api.ImageScan{Status: string(status.Status), Description: sdkaws.ToString(status.Description)}
		if summary := image.ImageScanFindingsSummary; summary != nil {
			result.Scan.CompletedAt = summary.ImageScanCompletedAt
			result.Scan.SourceUpdatedAt = summary.VulnerabilitySourceUpdatedAt
			if len(summary.FindingSeverityCounts) > 0 {
				result.Scan.Counts = map[string]int{}
				for severity, count := range summary.FindingSeverityCounts {
					result.Scan.Counts[severity] = int(count)
				}
			}
		}
	}
	return result
}

// shapeFindings flattens basic and enhanced findings, one per vulnerability and package, most
// severe first.
func shapeFindings(scan *ecr.DescribeImageScanFindingsOutput) []api.ImageFinding {
	findings := []api.ImageFinding{}
	if scan == nil || scan.ImageScanFindings == nil {
		return findings
	}
	for _, f := range scan.ImageScanFindings.Findings {
		finding := api.ImageFinding{ID: sdkaws.ToString(f.Name), Severity: string(f.Severity), URI: sdkaws.ToString(f.Uri)}
		for _, attr := range f.Attributes {
			switch sdkaws.ToString(attr.Key) {
			case "package_name":
				finding.Package = sdkaws.ToString(attr.Value)
			case "package_version":
				finding.Version = sdkaws.ToString(attr.Value)
			}
		}
		findings = append(findings, finding)
	}
	for _, f := range scan.ImageScanFindings.EnhancedFindings {
		details := f.PackageVulnerabilityDetails
		if details == nil {
			continue
		}
		base := api.ImageFinding{ID: sdkaws.ToString(details.VulnerabilityId), Severity: sdkaws.ToString(f.Severity), URI: sdkaws.ToString(details.SourceUrl)}
		if len(details.VulnerablePackages) == 0 {
			findings = append(findings, base)
		}
		for _, pkg := range details.VulnerablePackages {
			finding := base
			finding.Package, finding.Version, finding.FixedIn = sdkaws.ToString(pkg.Name), sdkaws.ToString(pkg.Version), sdkaws.ToString(pkg.FixedInVersion)
			findings = append(findings, finding)
		}
	}
	sort.SliceStable(findings, func(i, j int) bool {
		a, b := api.SeverityRank(findings[i].Severity), api.SeverityRank(findings[j].Severity)
		if a != b {
			return a < b
		}
		if findings[i].ID != findings[j].ID {
			return findings[i].ID < findings[j].ID
		}
		return findings[i].Package < findings[j].Package
	})
	return findings
}

// ecrSourceRef links to the repository in the ECR console when an image names its registry.
// Repository names are validated to [a-z0-9._/-], so they need no escaping in the path.
func ecrSourceRef(scope authz.ImageScope, repository, query string, images []ecrtypes.ImageDetail) api.SourceRef {
	ref := api.SourceRef{Kind: "ecr", Query: query}
	i := slices.IndexFunc(images, func(image ecrtypes.ImageDetail) bool {
		return sdkaws.ToString(image.RepositoryName) == repository && sdkaws.ToString(image.RegistryId) != ""
	})
	if i < 0 {
		return ref
	}
	region := scope.Source().AWS.Region
	ref.URL = fmt.Sprintf("https://%s.console.aws.amazon.com/ecr/repositories/private/%s/%s?region=%s",
		region, url.PathEscape(sdkaws.ToString(images[i].RegistryId)), repository, url.QueryEscape(region))
	return ref
}
