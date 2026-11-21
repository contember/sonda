package aws

import (
	"context"
	"errors"

	sdkaws "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/elasticache"
	ectypes "github.com/aws/aws-sdk-go-v2/service/elasticache/types"

	"github.com/contember/sonda/internal/apierr"
	"github.com/contember/sonda/internal/authz"
)

// elastiCacheAPI is the part of the ElastiCache client the connector uses: describe calls only.
type elastiCacheAPI interface {
	DescribeReplicationGroups(ctx context.Context, in *elasticache.DescribeReplicationGroupsInput, opts ...func(*elasticache.Options)) (*elasticache.DescribeReplicationGroupsOutput, error)
	DescribeCacheClusters(ctx context.Context, in *elasticache.DescribeCacheClustersInput, opts ...func(*elasticache.Options)) (*elasticache.DescribeCacheClustersOutput, error)
	DescribeCacheEngineVersions(ctx context.Context, in *elasticache.DescribeCacheEngineVersionsInput, opts ...func(*elasticache.Options)) (*elasticache.DescribeCacheEngineVersionsOutput, error)
	DescribeUpdateActions(ctx context.Context, in *elasticache.DescribeUpdateActionsInput, opts ...func(*elasticache.Options)) (*elasticache.DescribeUpdateActionsOutput, error)
}

// maxCacheVersions stops reading the engine version catalog of one engine; it holds far fewer.
const maxCacheVersions = 500

// openUpdateStatuses are the update action statuses that still need attention.
var openUpdateStatuses = []ectypes.UpdateActionStatus{
	ectypes.UpdateActionStatusNotApplied, ectypes.UpdateActionStatusWaitingToStart,
	ectypes.UpdateActionStatusInProgress, ectypes.UpdateActionStatusStopping,
	ectypes.UpdateActionStatusStopped, ectypes.UpdateActionStatusScheduling,
	ectypes.UpdateActionStatusScheduled,
}

// ReplicationGroup describes a bound replication group. One that does not exist is a
// configuration error.
func (c *Client) ReplicationGroup(ctx context.Context, scope authz.ResourceScope, id string) (ectypes.ReplicationGroup, error) {
	if !scope.HasElastiCache(id) {
		return ectypes.ReplicationGroup{}, c.outsideScope()
	}
	out, err := c.cache.DescribeReplicationGroups(ctx, &elasticache.DescribeReplicationGroupsInput{ReplicationGroupId: sdkaws.String(id)})
	var notFound *ectypes.ReplicationGroupNotFoundFault
	if errors.As(err, &notFound) {
		return ectypes.ReplicationGroup{}, apierr.Upstream("source %s: ElastiCache replication group %s not found", c.source.Name, id)
	}
	if err != nil {
		return ectypes.ReplicationGroup{}, c.apiError("DescribeReplicationGroups", err)
	}
	for _, group := range out.ReplicationGroups {
		if sdkaws.ToString(group.ReplicationGroupId) != id {
			return ectypes.ReplicationGroup{}, c.outsideScope()
		}
	}
	if len(out.ReplicationGroups) == 0 {
		return ectypes.ReplicationGroup{}, apierr.Upstream("source %s: ElastiCache replication group %s not found", c.source.Name, id)
	}
	return out.ReplicationGroups[0], nil
}

// CacheCluster describes a member cluster of a bound replication group, which must report the
// group as its own. The replication group carries no engine version or maintenance window;
// its members do.
func (c *Client) CacheCluster(ctx context.Context, scope authz.ResourceScope, group, id string) (ectypes.CacheCluster, error) {
	if !scope.HasElastiCache(group) {
		return ectypes.CacheCluster{}, c.outsideScope()
	}
	out, err := c.cache.DescribeCacheClusters(ctx, &elasticache.DescribeCacheClustersInput{CacheClusterId: sdkaws.String(id)})
	var notFound *ectypes.CacheClusterNotFoundFault
	if errors.As(err, &notFound) {
		return ectypes.CacheCluster{}, apierr.Upstream("source %s: ElastiCache cluster %s not found", c.source.Name, id)
	}
	if err != nil {
		return ectypes.CacheCluster{}, c.apiError("DescribeCacheClusters", err)
	}
	for _, cluster := range out.CacheClusters {
		if sdkaws.ToString(cluster.CacheClusterId) != id || sdkaws.ToString(cluster.ReplicationGroupId) != group {
			return ectypes.CacheCluster{}, c.outsideScope()
		}
	}
	if len(out.CacheClusters) == 0 {
		return ectypes.CacheCluster{}, apierr.Upstream("source %s: ElastiCache cluster %s not found", c.source.Name, id)
	}
	return out.CacheClusters[0], nil
}

// CacheEngineVersions lists the versions ElastiCache offers for an engine.
func (c *Client) CacheEngineVersions(ctx context.Context, engine string) ([]string, error) {
	var (
		versions []string
		marker   *string
	)
	for {
		out, err := c.cache.DescribeCacheEngineVersions(ctx, &elasticache.DescribeCacheEngineVersionsInput{
			Engine:     sdkaws.String(engine),
			MaxRecords: sdkaws.Int32(100),
			Marker:     marker,
		})
		if err != nil {
			return nil, c.apiError("DescribeCacheEngineVersions", err)
		}
		for _, v := range out.CacheEngineVersions {
			if sdkaws.ToString(v.Engine) == engine {
				versions = append(versions, sdkaws.ToString(v.EngineVersion))
			}
		}
		if out.Marker == nil || len(versions) >= maxCacheVersions {
			return versions, nil
		}
		marker = out.Marker
	}
}

// CacheUpdateActions returns the service updates of a bound replication group that are not
// complete.
func (c *Client) CacheUpdateActions(ctx context.Context, scope authz.ResourceScope, group string) ([]ectypes.UpdateAction, error) {
	if !scope.HasElastiCache(group) {
		return nil, c.outsideScope()
	}
	var (
		actions []ectypes.UpdateAction
		marker  *string
	)
	for {
		out, err := c.cache.DescribeUpdateActions(ctx, &elasticache.DescribeUpdateActionsInput{
			ReplicationGroupIds: []string{group},
			UpdateActionStatus:  openUpdateStatuses,
			MaxRecords:          sdkaws.Int32(100),
			Marker:              marker,
		})
		if err != nil {
			return nil, c.apiError("DescribeUpdateActions", err)
		}
		for _, action := range out.UpdateActions {
			if sdkaws.ToString(action.ReplicationGroupId) != group {
				return nil, c.outsideScope()
			}
		}
		actions = append(actions, out.UpdateActions...)
		if out.Marker == nil || len(actions) >= maxResourceEvents {
			return actions, nil
		}
		marker = out.Marker
	}
}
