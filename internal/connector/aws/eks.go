package aws

import (
	"context"
	"errors"

	sdkaws "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/eks"
	ekstypes "github.com/aws/aws-sdk-go-v2/service/eks/types"

	"github.com/contember/sonda/internal/apierr"
	"github.com/contember/sonda/internal/authz"
)

// eksAPI is the part of the EKS client the connector uses: describe and list calls only.
type eksAPI interface {
	DescribeCluster(ctx context.Context, in *eks.DescribeClusterInput, opts ...func(*eks.Options)) (*eks.DescribeClusterOutput, error)
	ListAddons(ctx context.Context, in *eks.ListAddonsInput, opts ...func(*eks.Options)) (*eks.ListAddonsOutput, error)
	DescribeAddon(ctx context.Context, in *eks.DescribeAddonInput, opts ...func(*eks.Options)) (*eks.DescribeAddonOutput, error)
	DescribeAddonVersions(ctx context.Context, in *eks.DescribeAddonVersionsInput, opts ...func(*eks.Options)) (*eks.DescribeAddonVersionsOutput, error)
	DescribeClusterVersions(ctx context.Context, in *eks.DescribeClusterVersionsInput, opts ...func(*eks.Options)) (*eks.DescribeClusterVersionsOutput, error)
}

// maxAddons stops the add-on list of one cluster; a cluster has far fewer.
const maxAddons = 50

// EKSCluster describes a bound cluster. One that does not exist is a configuration error.
func (c *Client) EKSCluster(ctx context.Context, scope authz.ResourceScope, name string) (ekstypes.Cluster, error) {
	if !scope.HasEKSCluster(name) {
		return ekstypes.Cluster{}, c.outsideScope()
	}
	out, err := c.eks.DescribeCluster(ctx, &eks.DescribeClusterInput{Name: sdkaws.String(name)})
	var notFound *ekstypes.ResourceNotFoundException
	if errors.As(err, &notFound) || (err == nil && out.Cluster == nil) {
		return ekstypes.Cluster{}, apierr.Upstream("source %s: EKS cluster %s not found", c.source.Name, name)
	}
	if err != nil {
		return ekstypes.Cluster{}, c.apiError("DescribeCluster", err)
	}
	if sdkaws.ToString(out.Cluster.Name) != name {
		return ekstypes.Cluster{}, c.outsideScope()
	}
	return *out.Cluster, nil
}

// EKSAddons lists and describes up to maxAddons add-ons of a bound cluster and reports whether
// more exist.
func (c *Client) EKSAddons(ctx context.Context, scope authz.ResourceScope, cluster string) ([]ekstypes.Addon, bool, error) {
	if !scope.HasEKSCluster(cluster) {
		return nil, false, c.outsideScope()
	}
	var (
		names     []string
		next      *string
		truncated bool
	)
	for {
		out, err := c.eks.ListAddons(ctx, &eks.ListAddonsInput{ClusterName: sdkaws.String(cluster), MaxResults: sdkaws.Int32(maxAddons), NextToken: next})
		if err != nil {
			return nil, false, c.apiError("ListAddons", err)
		}
		names = append(names, out.Addons...)
		if len(names) >= maxAddons {
			truncated = len(names) > maxAddons || out.NextToken != nil
			names = names[:maxAddons]
			break
		}
		if out.NextToken == nil {
			break
		}
		next = out.NextToken
	}
	addons := make([]ekstypes.Addon, 0, len(names))
	for _, name := range names {
		out, err := c.eks.DescribeAddon(ctx, &eks.DescribeAddonInput{ClusterName: sdkaws.String(cluster), AddonName: sdkaws.String(name)})
		if err != nil {
			return nil, false, c.apiError("DescribeAddon", err)
		}
		if out.Addon == nil {
			continue
		}
		if sdkaws.ToString(out.Addon.ClusterName) != cluster || sdkaws.ToString(out.Addon.AddonName) != name {
			return nil, false, c.outsideScope()
		}
		addons = append(addons, *out.Addon)
	}
	return addons, truncated, nil
}

// EKSAddonVersions lists the versions of an add-on compatible with a Kubernetes version, from
// the EKS catalog.
func (c *Client) EKSAddonVersions(ctx context.Context, addon, kubernetesVersion string) ([]ekstypes.AddonVersionInfo, error) {
	var (
		versions []ekstypes.AddonVersionInfo
		next     *string
	)
	for {
		out, err := c.eks.DescribeAddonVersions(ctx, &eks.DescribeAddonVersionsInput{
			AddonName:         sdkaws.String(addon),
			KubernetesVersion: sdkaws.String(kubernetesVersion),
			MaxResults:        sdkaws.Int32(100),
			NextToken:         next,
		})
		if err != nil {
			return nil, c.apiError("DescribeAddonVersions", err)
		}
		for _, info := range out.Addons {
			if sdkaws.ToString(info.AddonName) == addon {
				versions = append(versions, info.AddonVersions...)
			}
		}
		if out.NextToken == nil || len(versions) >= maxCacheVersions {
			return versions, nil
		}
		next = out.NextToken
	}
}

// EKSClusterVersion returns the support dates of a Kubernetes version from the EKS catalog, or
// false when EKS no longer lists it.
func (c *Client) EKSClusterVersion(ctx context.Context, version string) (ekstypes.ClusterVersionInformation, bool, error) {
	out, err := c.eks.DescribeClusterVersions(ctx, &eks.DescribeClusterVersionsInput{
		// Alone it also returns unsupported versions; EKS rejects it combined with includeAll.
		ClusterVersions: []string{version},
	})
	if err != nil {
		return ekstypes.ClusterVersionInformation{}, false, c.apiError("DescribeClusterVersions", err)
	}
	for _, info := range out.ClusterVersions {
		if sdkaws.ToString(info.ClusterVersion) == version {
			return info, true, nil
		}
	}
	return ekstypes.ClusterVersionInformation{}, false, nil
}
