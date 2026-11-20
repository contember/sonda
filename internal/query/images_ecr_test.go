package query

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	sdkaws "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"

	"github.com/contember/sonda/api"
	"github.com/contember/sonda/internal/apierr"
	"github.com/contember/sonda/internal/authz"
	"github.com/contember/sonda/internal/config"
	"github.com/contember/sonda/internal/connector/aws"
	"github.com/contember/sonda/internal/identities"
)

// fakeRegistry answers the ECR JSON protocol: repository "shop" holds three images,
// "shop-worker" one image with a completed basic scan.
func fakeRegistry(t *testing.T) *httptest.Server {
	t.Helper()
	digest := func(i int) string { return fmt.Sprintf("sha256:%064d", i) }
	images := map[string][]map[string]any{
		"shop": {
			{"repositoryName": "shop", "registryId": "123456789012", "imageDigest": digest(1), "imageTags": []string{"v1"}, "imagePushedAt": 1763600000},
			{"repositoryName": "shop", "registryId": "123456789012", "imageDigest": digest(3), "imageTags": []string{"v3"}, "imagePushedAt": 1763800000},
			{"repositoryName": "shop", "registryId": "123456789012", "imageDigest": digest(2), "imagePushedAt": 1763700000},
		},
		"shop-worker": {
			{"repositoryName": "shop-worker", "registryId": "123456789012", "imageDigest": digest(9), "imagePushedAt": 1763900000,
				"imageScanStatus":          map[string]any{"status": "COMPLETE"},
				"imageScanFindingsSummary": map[string]any{"findingSeverityCounts": map[string]int{"HIGH": 1, "CRITICAL": 1}, "imageScanCompletedAt": 1763900100}},
		},
	}
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var in struct {
			RepositoryName string `json:"repositoryName"`
			ImageIds       []struct {
				ImageDigest string `json:"imageDigest"`
			} `json:"imageIds"`
			ImageID struct {
				ImageDigest string `json:"imageDigest"`
			} `json:"imageId"`
		}
		body, _ := io.ReadAll(r.Body)
		if err := json.Unmarshal(body, &in); err != nil {
			t.Errorf("request body: %v", err)
		}
		w.Header().Set("Content-Type", "application/x-amz-json-1.1")
		notFound := func(kind string) {
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprintf(w, `{"__type":"%s","message":"not found"}`, kind)
		}
		repo := images[in.RepositoryName]
		switch target := r.Header.Get("X-Amz-Target"); {
		case strings.HasSuffix(target, ".DescribeImages") && len(in.ImageIds) > 0:
			for _, image := range repo {
				if image["imageDigest"] == in.ImageIds[0].ImageDigest {
					json.NewEncoder(w).Encode(map[string]any{"imageDetails": []any{image}})
					return
				}
			}
			notFound("ImageNotFoundException")
		case strings.HasSuffix(target, ".DescribeImages"):
			json.NewEncoder(w).Encode(map[string]any{"imageDetails": repo})
		case strings.HasSuffix(target, ".DescribeImageScanFindings"):
			if in.RepositoryName != "shop-worker" {
				notFound("ScanNotFoundException")
				return
			}
			json.NewEncoder(w).Encode(map[string]any{
				"repositoryName":  in.RepositoryName,
				"imageId":         map[string]any{"imageDigest": in.ImageID.ImageDigest},
				"imageScanStatus": map[string]any{"status": "COMPLETE"},
				"imageScanFindings": map[string]any{"findings": []any{
					map[string]any{"name": "CVE-2", "severity": "HIGH", "attributes": []any{map[string]string{"key": "package_name", "value": "busybox"}}},
					map[string]any{"name": "CVE-1", "severity": "CRITICAL", "attributes": []any{map[string]string{"key": "package_name", "value": "openssl"}}},
				}},
			})
		default:
			t.Errorf("unexpected call %s", target)
			w.WriteHeader(http.StatusBadRequest)
		}
	}))
}

func registryService(t *testing.T) (*Service, *authz.Identity) {
	t.Helper()
	server := fakeRegistry(t)
	t.Cleanup(server.Close)
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
	sdk := sdkaws.Config{
		Region:           "eu-central-1",
		Credentials:      credentials.NewStaticCredentialsProvider("AKIDTEST", "secret", ""),
		BaseEndpoint:     sdkaws.String(server.URL),
		RetryMaxAttempts: 1,
	}
	connectors := Connectors{AWS: map[string]*aws.Client{"aws": aws.New(cfg.Sources["aws"], sdk)}}
	s, err := New(cfg, authz.New(cfg, nil), connectors, nil)
	if err != nil {
		t.Fatal(err)
	}
	return s, &authz.Identity{Name: "agent", Grants: []identities.Grant{
		{Project: "shop", Environment: "production", Capability: api.CapabilityImages},
	}}
}

func TestImagesNewestFirstThroughECR(t *testing.T) {
	s, identity := registryService(t)
	resp, err := s.Images(context.Background(), identity, "web", api.ImagesRequest{Repository: "shop", Limit: 2})
	if err != nil {
		t.Fatal(err)
	}
	if len(resp.Data) != 2 || resp.Data[0].Tags[0] != "v3" || resp.Data[1].Digest != fmt.Sprintf("sha256:%064d", 2) || !resp.Meta.Truncated {
		t.Errorf("images = %+v, truncated = %v", resp.Data, resp.Meta.Truncated)
	}
	if resp.Data[0].PushedAt == nil || resp.Data[0].PushedAt.Unix() != 1763800000 {
		t.Errorf("pushedAt = %v", resp.Data[0].PushedAt)
	}
	if len(resp.Meta.Sources) != 1 || !strings.Contains(resp.Meta.Sources[0].URL, "/ecr/repositories/private/123456789012/shop?region=eu-central-1") {
		t.Errorf("sources = %+v", resp.Meta.Sources)
	}
}

func TestImagesByDigestAcrossRepositories(t *testing.T) {
	s, identity := registryService(t)
	running := fmt.Sprintf("sha256:%064d", 9)
	resp, err := s.Images(context.Background(), identity, "web", api.ImagesRequest{Digests: []string{running, running}})
	if err != nil {
		t.Fatal(err)
	}
	if len(resp.Data) != 1 || resp.Data[0].Repository != "shop-worker" || resp.Meta.Truncated {
		t.Fatalf("images = %+v", resp.Data)
	}
	if scan := resp.Data[0].Scan; scan == nil || scan.Status != "COMPLETE" || scan.Counts["CRITICAL"] != 1 {
		t.Errorf("scan = %+v", scan)
	}
}

func TestImageDetailThroughECR(t *testing.T) {
	s, identity := registryService(t)
	resp, err := s.Image(context.Background(), identity, "web", fmt.Sprintf("sha256:%064d", 9), api.ImagesRequest{Limit: 1})
	if err != nil {
		t.Fatal(err)
	}
	if got := resp.Data.Findings; len(got) != 1 || got[0].ID != "CVE-1" || got[0].Package != "openssl" || !resp.Meta.Truncated {
		t.Errorf("findings = %+v, truncated = %v", got, resp.Meta.Truncated)
	}

	resp, err = s.Image(context.Background(), identity, "web", fmt.Sprintf("sha256:%064d", 1), api.ImagesRequest{})
	if err != nil || resp.Data.Scan != nil || len(resp.Data.Findings) != 0 {
		t.Errorf("never scanned: %+v, err = %v", resp.Data, err)
	}

	_, err = s.Image(context.Background(), identity, "web", fmt.Sprintf("sha256:%064d", 7), api.ImagesRequest{})
	if apiErr, ok := apierr.As(err); !ok || apiErr.Code != api.CodeNotFound {
		t.Errorf("unknown digest: error = %v", err)
	}
}
