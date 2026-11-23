package aws

import (
	"context"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"testing"

	sdkaws "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ecr"
	ecrtypes "github.com/aws/aws-sdk-go-v2/service/ecr/types"

	"github.com/contember/sonda/api"
	"github.com/contember/sonda/internal/apierr"
	"github.com/contember/sonda/internal/authz"
	"github.com/contember/sonda/internal/config"
	"github.com/contember/sonda/internal/identities"
)

const testDigest = "sha256:0994af66bd88ce73c84ee33852b7a81a8ddef37e5c55187df223fb06d3b6deff"

func imageScope(t *testing.T) (*config.Config, authz.ImageScope) {
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
            images: { source: aws, repositories: [shop] }
`), func(string) (string, bool) { return "", false })
	if err != nil {
		t.Fatal(err)
	}
	identity := &authz.Identity{Name: "agent", Grants: []identities.Grant{
		{Project: "shop", Environment: "production", Capability: api.CapabilityImages},
	}}
	scope, err := authz.New(cfg, nil).ImageScope(identity, "web", "production")
	if err != nil {
		t.Fatal(err)
	}
	return cfg, scope
}

// fakeECR holds count images of repository "shop" and findings pages of one image.
type fakeECR struct {
	count       int
	repoName    string // the repository name in responses; "shop" by default
	otherDigest bool   // responses name another digest than requested
	missing     bool   // DescribeImages by digest answers ImageNotFoundException
	noScan      bool
	findings    [][]ecrtypes.ImageScanFinding
	describes   []*ecr.DescribeImagesInput
	index       string                    // the manifest BatchGetImage returns
	failure     ecrtypes.ImageFailureCode // BatchGetImage reports this failure instead
}

func (f *fakeECR) repo() string {
	if f.repoName == "" {
		return "shop"
	}
	return f.repoName
}

func (f *fakeECR) digest(requested *string) *string {
	if f.otherDigest {
		return sdkaws.String("sha256:" + strings.Repeat("0", 64))
	}
	return requested
}

func (f *fakeECR) DescribeImages(_ context.Context, in *ecr.DescribeImagesInput, _ ...func(*ecr.Options)) (*ecr.DescribeImagesOutput, error) {
	f.describes = append(f.describes, in)
	if len(in.ImageIds) > 0 {
		if f.missing {
			return nil, &ecrtypes.ImageNotFoundException{Message: sdkaws.String("not found")}
		}
		return &ecr.DescribeImagesOutput{ImageDetails: []ecrtypes.ImageDetail{{RepositoryName: sdkaws.String(f.repo()), ImageDigest: f.digest(in.ImageIds[0].ImageDigest)}}}, nil
	}
	start := 0
	if in.NextToken != nil {
		start, _ = strconv.Atoi(*in.NextToken)
	}
	end := min(start+int(sdkaws.ToInt32(in.MaxResults)), f.count)
	out := &ecr.DescribeImagesOutput{}
	for i := start; i < end; i++ {
		out.ImageDetails = append(out.ImageDetails, ecrtypes.ImageDetail{RepositoryName: sdkaws.String(f.repo()), ImageDigest: sdkaws.String(fmt.Sprintf("sha256:%064d", i))})
	}
	if end < f.count {
		out.NextToken = sdkaws.String(strconv.Itoa(end))
	}
	return out, nil
}

func (f *fakeECR) DescribeImageScanFindings(_ context.Context, in *ecr.DescribeImageScanFindingsInput, _ ...func(*ecr.Options)) (*ecr.DescribeImageScanFindingsOutput, error) {
	if f.noScan {
		return nil, &ecrtypes.ScanNotFoundException{Message: sdkaws.String("no scan")}
	}
	page := 0
	if in.NextToken != nil {
		page, _ = strconv.Atoi(*in.NextToken)
	}
	out := &ecr.DescribeImageScanFindingsOutput{
		RepositoryName:    sdkaws.String(f.repo()),
		ImageId:           &ecrtypes.ImageIdentifier{ImageDigest: f.digest(in.ImageId.ImageDigest)},
		ImageScanStatus:   &ecrtypes.ImageScanStatus{Status: ecrtypes.ScanStatusComplete},
		ImageScanFindings: &ecrtypes.ImageScanFindings{Findings: f.findings[page]},
	}
	if page+1 < len(f.findings) {
		out.NextToken = sdkaws.String(strconv.Itoa(page + 1))
	}
	return out, nil
}

func (f *fakeECR) BatchGetImage(_ context.Context, in *ecr.BatchGetImageInput, _ ...func(*ecr.Options)) (*ecr.BatchGetImageOutput, error) {
	if f.failure != "" {
		return &ecr.BatchGetImageOutput{Failures: []ecrtypes.ImageFailure{{ImageId: &in.ImageIds[0], FailureCode: f.failure, FailureReason: sdkaws.String("reason")}}}, nil
	}
	return &ecr.BatchGetImageOutput{Images: []ecrtypes.Image{{
		RepositoryName: sdkaws.String(f.repo()),
		ImageId:        &ecrtypes.ImageIdentifier{ImageDigest: f.digest(in.ImageIds[0].ImageDigest)},
		ImageManifest:  sdkaws.String(f.index),
	}}}, nil
}

func ecrClient(cfg *config.Config, fake *fakeECR) *Client {
	c := newClient(cfg.Sources["aws"], nil, nil, &fakeIdentity{})
	c.ecr = fake
	return c
}

func TestImageByDigest(t *testing.T) {
	cfg, scope := imageScope(t)
	fake := &fakeECR{}
	image, found, err := ecrClient(cfg, fake).Image(context.Background(), scope, "shop", testDigest)
	if err != nil || !found || sdkaws.ToString(image.ImageDigest) != testDigest {
		t.Fatalf("image = %+v, found = %v, err = %v", image, found, err)
	}
	if in := fake.describes[0]; sdkaws.ToString(in.RepositoryName) != "shop" || sdkaws.ToString(in.ImageIds[0].ImageDigest) != testDigest {
		t.Errorf("DescribeImages input = %+v", in)
	}

	_, found, err = ecrClient(cfg, &fakeECR{missing: true}).Image(context.Background(), scope, "shop", testDigest)
	if err != nil || found {
		t.Errorf("missing image: found = %v, err = %v", found, err)
	}
}

func TestImagesRejectOutsideScope(t *testing.T) {
	cfg, scope := imageScope(t)
	_, _, err := ecrClient(cfg, &fakeECR{}).Image(context.Background(), scope, "other", testDigest)
	if apiErr, ok := apierr.As(err); !ok || apiErr.Code != api.CodeInternal {
		t.Errorf("unbound repository: error = %v", err)
	}
	_, _, err = ecrClient(cfg, &fakeECR{count: 1, repoName: "other"}).Images(context.Background(), scope, "shop")
	if apiErr, ok := apierr.As(err); !ok || apiErr.Code != api.CodeInternal || !strings.Contains(err.Error(), "outside the scope") {
		t.Errorf("image of another repository: error = %v", err)
	}
}

func TestImagesPageAndTruncate(t *testing.T) {
	cfg, scope := imageScope(t)
	images, truncated, err := ecrClient(cfg, &fakeECR{count: 2500}).Images(context.Background(), scope, "shop")
	if err != nil || len(images) != 2500 || truncated {
		t.Errorf("images = %d, truncated = %v, err = %v", len(images), truncated, err)
	}
	images, truncated, err = ecrClient(cfg, &fakeECR{count: maxRepositoryImages + 1}).Images(context.Background(), scope, "shop")
	if err != nil || len(images) != maxRepositoryImages || !truncated {
		t.Errorf("over the cap: images = %d, truncated = %v, err = %v", len(images), truncated, err)
	}
}

func TestScanFindingsMergePages(t *testing.T) {
	cfg, scope := imageScope(t)
	finding := func(name string) ecrtypes.ImageScanFinding {
		return ecrtypes.ImageScanFinding{Name: sdkaws.String(name), Severity: ecrtypes.FindingSeverityHigh}
	}
	fake := &fakeECR{findings: [][]ecrtypes.ImageScanFinding{{finding("CVE-1"), finding("CVE-2")}, {finding("CVE-3")}}}
	scan, truncated, err := ecrClient(cfg, fake).ScanFindings(context.Background(), scope, "shop", testDigest)
	if err != nil || truncated {
		t.Fatalf("truncated = %v, err = %v", truncated, err)
	}
	if got := len(scan.ImageScanFindings.Findings); got != 3 || scan.ImageScanStatus.Status != ecrtypes.ScanStatusComplete {
		t.Errorf("findings = %d, status = %+v", got, scan.ImageScanStatus)
	}

	scan, _, err = ecrClient(cfg, &fakeECR{noScan: true}).ScanFindings(context.Background(), scope, "shop", testDigest)
	if err != nil || scan != nil {
		t.Errorf("never scanned: scan = %+v, err = %v", scan, err)
	}
	summary, err := ecrClient(cfg, &fakeECR{noScan: true}).Scan(context.Background(), scope, "shop", testDigest)
	if err != nil || summary != nil {
		t.Errorf("never scanned, summary: scan = %+v, err = %v", summary, err)
	}
}

func TestECRPostChecks(t *testing.T) {
	cfg, scope := imageScope(t)
	findings := [][]ecrtypes.ImageScanFinding{{}}
	cases := []struct {
		name string
		fake *fakeECR
		call func(*Client) error
	}{
		{"image of another digest", &fakeECR{otherDigest: true}, func(c *Client) error {
			_, _, err := c.Image(context.Background(), scope, "shop", testDigest)
			return err
		}},
		{"image of another repository", &fakeECR{repoName: "other"}, func(c *Client) error {
			_, _, err := c.Image(context.Background(), scope, "shop", testDigest)
			return err
		}},
		{"scan of another digest", &fakeECR{otherDigest: true, findings: findings}, func(c *Client) error {
			_, _, err := c.ScanFindings(context.Background(), scope, "shop", testDigest)
			return err
		}},
		{"scan of another repository", &fakeECR{repoName: "other", findings: findings}, func(c *Client) error {
			_, _, err := c.ScanFindings(context.Background(), scope, "shop", testDigest)
			return err
		}},
		{"index of another digest", &fakeECR{otherDigest: true, index: `{"manifests":[]}`}, func(c *Client) error {
			_, _, err := c.PlatformManifests(context.Background(), scope, "shop", testDigest)
			return err
		}},
		{"index of another repository", &fakeECR{repoName: "other", index: `{"manifests":[]}`}, func(c *Client) error {
			_, _, err := c.PlatformManifests(context.Background(), scope, "shop", testDigest)
			return err
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.call(ecrClient(cfg, tc.fake))
			if apiErr, ok := apierr.As(err); !ok || apiErr.Code != api.CodeInternal || !strings.Contains(err.Error(), "outside the scope") {
				t.Errorf("error = %v", err)
			}
		})
	}
}

func TestPlatformManifestsLeaveOutAttestations(t *testing.T) {
	cfg, scope := imageScope(t)
	digest := func(c string) string { return "sha256:" + strings.Repeat(c, 64) }
	// The shape buildx pushes: image manifests per platform, an attestation manifest for each.
	index := `{
	  "schemaVersion": 2,
	  "mediaType": "application/vnd.oci.image.index.v1+json",
	  "manifests": [
	    {"mediaType": "application/vnd.oci.image.manifest.v1+json", "digest": "` + digest("a") + `", "size": 3703, "platform": {"architecture": "amd64", "os": "linux"}},
	    {"mediaType": "application/vnd.oci.image.manifest.v1+json", "digest": "` + digest("b") + `", "size": 3703, "platform": {"architecture": "arm", "os": "linux", "variant": "v7"}},
	    {"mediaType": "application/vnd.oci.image.manifest.v1+json", "digest": "` + digest("c") + `", "size": 838,
	     "annotations": {"vnd.docker.reference.digest": "` + digest("a") + `", "vnd.docker.reference.type": "attestation-manifest"},
	     "platform": {"architecture": "unknown", "os": "unknown"}},
	    {"mediaType": "application/vnd.oci.image.index.v1+json", "digest": "` + digest("d") + `", "size": 500}
	  ]
	}`
	manifests, truncated, err := ecrClient(cfg, &fakeECR{index: index}).PlatformManifests(context.Background(), scope, "shop", testDigest)
	want := []PlatformManifest{{Digest: digest("a"), Platform: "linux/amd64"}, {Digest: digest("b"), Platform: "linux/arm/v7"}}
	if err != nil || truncated || !slices.Equal(manifests, want) {
		t.Errorf("manifests = %+v, truncated = %v, err = %v", manifests, truncated, err)
	}

	many := make([]string, maxPlatformManifests+1)
	for i := range many {
		many[i] = fmt.Sprintf(`{"mediaType": "application/vnd.docker.distribution.manifest.v2+json", "digest": "sha256:%064x", "platform": {"os": "linux", "architecture": "amd64"}}`, i)
	}
	manifests, truncated, err = ecrClient(cfg, &fakeECR{index: `{"manifests": [` + strings.Join(many, ",") + `]}`}).PlatformManifests(context.Background(), scope, "shop", testDigest)
	if err != nil || !truncated || len(manifests) != maxPlatformManifests {
		t.Errorf("over the cap: manifests = %d, truncated = %v, err = %v", len(manifests), truncated, err)
	}

	manifests, _, err = ecrClient(cfg, &fakeECR{failure: ecrtypes.ImageFailureCodeImageNotFound}).PlatformManifests(context.Background(), scope, "shop", testDigest)
	if err != nil || len(manifests) != 0 {
		t.Errorf("deleted index: manifests = %+v, err = %v", manifests, err)
	}
}

func TestPlatformManifestsRejectBadIndex(t *testing.T) {
	cfg, scope := imageScope(t)
	cases := map[string]*fakeECR{
		"not JSON":       {index: "{"},
		"invalid digest": {index: `{"manifests": [{"mediaType": "application/vnd.oci.image.manifest.v1+json", "digest": "sha256:abc"}]}`},
		"other failure":  {failure: ecrtypes.ImageFailureCodeKmsError},
	}
	for name, fake := range cases {
		t.Run(name, func(t *testing.T) {
			_, _, err := ecrClient(cfg, fake).PlatformManifests(context.Background(), scope, "shop", testDigest)
			if apiErr, ok := apierr.As(err); !ok || apiErr.Code != api.CodeUpstreamError || strings.Contains(err.Error(), "reason") {
				t.Errorf("error = %v", err)
			}
		})
	}
}
