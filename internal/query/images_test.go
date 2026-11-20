package query

import (
	"context"
	"strings"
	"testing"
	"time"

	sdkaws "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ecr"
	ecrtypes "github.com/aws/aws-sdk-go-v2/service/ecr/types"

	"github.com/contember/sonda/api"
	"github.com/contember/sonda/internal/apierr"
	"github.com/contember/sonda/internal/authz"
	"github.com/contember/sonda/internal/config"
	"github.com/contember/sonda/internal/identities"
)

const digestA = "sha256:0994af66bd88ce73c84ee33852b7a81a8ddef37e5c55187df223fb06d3b6deff"

// imagesService has no connectors: every case here fails before calling AWS.
func imagesService(t *testing.T) (*Service, *authz.Identity) {
	t.Helper()
	cfg, err := config.Parse([]byte(`
sources:
  aws: { type: aws, region: eu-central-1 }
projects:
  shop:
    services:
      web:
        environments:
          production:
            images: { source: aws, repositories: [shop, shop-worker] }
`), func(string) (string, bool) { return "", false })
	if err != nil {
		t.Fatal(err)
	}
	identity := &authz.Identity{Name: "agent", Grants: []identities.Grant{
		{Project: "shop", Environment: "production", Capability: api.CapabilityImages},
	}}
	return &Service{cfg: cfg, authz: authz.New(cfg, nil)}, identity
}

func TestImagesValidateRequests(t *testing.T) {
	s, identity := imagesService(t)
	many := make([]string, 26)
	for i := range many {
		many[i] = digestA
	}
	tests := []struct {
		name string
		req  api.ImagesRequest
		code api.ErrorCode
		want string
	}{
		{"unbound repository", api.ImagesRequest{Repository: "other"}, api.CodeNotFound, `repository "other" is not bound to web/production`},
		{"tag instead of digest", api.ImagesRequest{Digests: []string{"latest"}}, api.CodeInvalidRequest, `digest "latest" must be sha256:`},
		{"uppercase digest", api.ImagesRequest{Digests: []string{strings.ToUpper(digestA)}}, api.CodeInvalidRequest, "must be sha256:"},
		{"too many lookups", api.ImagesRequest{Digests: many}, api.CodeInvalidRequest, "26 digests in 2 repositories need 52 lookups"},
		{"limit over maximum", api.ImagesRequest{Limit: maxImages + 1}, api.CodeInvalidRequest, "limit must be between 1 and 100"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := s.Images(context.Background(), identity, "web", tt.req)
			if apiErr, ok := apierr.As(err); !ok || apiErr.Code != tt.code || !strings.Contains(err.Error(), tt.want) {
				t.Errorf("error = %v, want %s containing %q", err, tt.code, tt.want)
			}
		})
	}

	_, err := s.Image(context.Background(), identity, "web", "sha256:abc", api.ImagesRequest{})
	if apiErr, ok := apierr.As(err); !ok || apiErr.Code != api.CodeInvalidRequest {
		t.Errorf("short digest: error = %v", err)
	}
	_, err = s.Images(context.Background(), &authz.Identity{Name: "other"}, "web", api.ImagesRequest{})
	if apiErr, ok := apierr.As(err); !ok || apiErr.Code != api.CodeNotFound {
		t.Errorf("no grant: error = %v", err)
	}
}

func TestShapeImage(t *testing.T) {
	pushed := time.Date(2026, 11, 20, 10, 0, 0, 0, time.UTC)
	image := shapeImage(ecrtypes.ImageDetail{
		RepositoryName:   sdkaws.String("shop"),
		ImageDigest:      sdkaws.String(digestA),
		ImageTags:        []string{"v2", "latest"},
		ImagePushedAt:    &pushed,
		ImageSizeInBytes: sdkaws.Int64(1024),
		ImageScanStatus:  &ecrtypes.ImageScanStatus{Status: ecrtypes.ScanStatusComplete},
		ImageScanFindingsSummary: &ecrtypes.ImageScanFindingsSummary{
			ImageScanCompletedAt:  &pushed,
			FindingSeverityCounts: map[string]int32{"HIGH": 2, "CRITICAL": 1},
		},
	})
	if image.Repository != "shop" || image.Digest != digestA || strings.Join(image.Tags, ",") != "latest,v2" || image.SizeBytes != 1024 {
		t.Errorf("image = %+v", image)
	}
	if image.Scan == nil || image.Scan.Status != "COMPLETE" || image.Scan.Counts["CRITICAL"] != 1 || image.Scan.Counts["HIGH"] != 2 || image.Scan.CompletedAt == nil {
		t.Errorf("scan = %+v", image.Scan)
	}
	if never := shapeImage(ecrtypes.ImageDetail{RepositoryName: sdkaws.String("shop")}); never.Scan != nil || never.Tags == nil {
		t.Errorf("unscanned untagged image = %+v", never)
	}
}

func TestShapeFindingsMostSevereFirst(t *testing.T) {
	attrs := func(name, version string) []ecrtypes.Attribute {
		return []ecrtypes.Attribute{{Key: sdkaws.String("package_name"), Value: sdkaws.String(name)}, {Key: sdkaws.String("package_version"), Value: sdkaws.String(version)}}
	}
	scan := &ecr.DescribeImageScanFindingsOutput{ImageScanFindings: &ecrtypes.ImageScanFindings{
		Findings: []ecrtypes.ImageScanFinding{
			{Name: sdkaws.String("CVE-2024-2"), Severity: ecrtypes.FindingSeverityMedium, Attributes: attrs("busybox", "1.36")},
			{Name: sdkaws.String("CVE-2024-1"), Severity: ecrtypes.FindingSeverityCritical, Uri: sdkaws.String("https://example.com/CVE-2024-1"), Attributes: attrs("openssl", "3.1.0")},
		},
		EnhancedFindings: []ecrtypes.EnhancedImageScanFinding{{
			Severity: sdkaws.String("HIGH"),
			PackageVulnerabilityDetails: &ecrtypes.PackageVulnerabilityDetails{
				VulnerabilityId: sdkaws.String("GHSA-xxxx"),
				VulnerablePackages: []ecrtypes.VulnerablePackage{
					{Name: sdkaws.String("undici"), Version: sdkaws.String("5.0.0"), FixedInVersion: sdkaws.String("5.28.4")},
					{Name: sdkaws.String("ws"), Version: sdkaws.String("8.0.0")},
				},
			},
		}},
	}}
	got := shapeFindings(scan)
	want := []api.ImageFinding{
		{ID: "CVE-2024-1", Severity: "CRITICAL", Package: "openssl", Version: "3.1.0", URI: "https://example.com/CVE-2024-1"},
		{ID: "GHSA-xxxx", Severity: "HIGH", Package: "undici", Version: "5.0.0", FixedIn: "5.28.4"},
		{ID: "GHSA-xxxx", Severity: "HIGH", Package: "ws", Version: "8.0.0"},
		{ID: "CVE-2024-2", Severity: "MEDIUM", Package: "busybox", Version: "1.36"},
	}
	if len(got) != len(want) {
		t.Fatalf("findings = %+v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("finding %d = %+v, want %+v", i, got[i], want[i])
		}
	}
	if none := shapeFindings(nil); none == nil || len(none) != 0 {
		t.Errorf("no scan = %#v, want an empty list", none)
	}
}
