package aws

import (
	"context"
	"errors"
	"strings"
	"time"

	sdkaws "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/rds"
	rdstypes "github.com/aws/aws-sdk-go-v2/service/rds/types"

	"github.com/contember/sonda/internal/apierr"
	"github.com/contember/sonda/internal/authz"
)

// rdsAPI is the part of the RDS client the connector uses: describe calls only.
type rdsAPI interface {
	DescribeDBClusters(ctx context.Context, in *rds.DescribeDBClustersInput, opts ...func(*rds.Options)) (*rds.DescribeDBClustersOutput, error)
	DescribeDBInstances(ctx context.Context, in *rds.DescribeDBInstancesInput, opts ...func(*rds.Options)) (*rds.DescribeDBInstancesOutput, error)
	DescribeDBEngineVersions(ctx context.Context, in *rds.DescribeDBEngineVersionsInput, opts ...func(*rds.Options)) (*rds.DescribeDBEngineVersionsOutput, error)
	DescribeDBMajorEngineVersions(ctx context.Context, in *rds.DescribeDBMajorEngineVersionsInput, opts ...func(*rds.Options)) (*rds.DescribeDBMajorEngineVersionsOutput, error)
	DescribePendingMaintenanceActions(ctx context.Context, in *rds.DescribePendingMaintenanceActionsInput, opts ...func(*rds.Options)) (*rds.DescribePendingMaintenanceActionsOutput, error)
	DescribeDBClusterSnapshots(ctx context.Context, in *rds.DescribeDBClusterSnapshotsInput, opts ...func(*rds.Options)) (*rds.DescribeDBClusterSnapshotsOutput, error)
	DescribeDBSnapshots(ctx context.Context, in *rds.DescribeDBSnapshotsInput, opts ...func(*rds.Options)) (*rds.DescribeDBSnapshotsOutput, error)
	DescribeEvents(ctx context.Context, in *rds.DescribeEventsInput, opts ...func(*rds.Options)) (*rds.DescribeEventsOutput, error)
}

const (
	// rdsPage is the most records an RDS describe call returns.
	rdsPage = 100
	// maxSnapshots stops reading the snapshots of one database; RDS returns them in no order,
	// so the newest are found among those read.
	maxSnapshots = 500
	// maxResourceEvents stops reading the events of one database.
	maxResourceEvents = 500
)

// RDSCluster describes a bound DB cluster. A cluster that does not exist is a configuration
// error.
func (c *Client) RDSCluster(ctx context.Context, scope authz.ResourceScope, id string) (rdstypes.DBCluster, error) {
	if !scope.HasRDSCluster(id) {
		return rdstypes.DBCluster{}, c.outsideScope()
	}
	out, err := c.rds.DescribeDBClusters(ctx, &rds.DescribeDBClustersInput{DBClusterIdentifier: sdkaws.String(id)})
	var notFound *rdstypes.DBClusterNotFoundFault
	if errors.As(err, &notFound) {
		return rdstypes.DBCluster{}, apierr.Upstream("source %s: DB cluster %s not found", c.source.Name, id)
	}
	if err != nil {
		return rdstypes.DBCluster{}, c.apiError("DescribeDBClusters", err)
	}
	for _, cluster := range out.DBClusters {
		if !strings.EqualFold(sdkaws.ToString(cluster.DBClusterIdentifier), id) {
			return rdstypes.DBCluster{}, c.outsideScope()
		}
	}
	if len(out.DBClusters) == 0 {
		return rdstypes.DBCluster{}, apierr.Upstream("source %s: DB cluster %s not found", c.source.Name, id)
	}
	return out.DBClusters[0], nil
}

// RDSInstance describes a DB instance: a bound standalone instance when cluster is empty,
// otherwise a member of the bound cluster, which the instance must report as its cluster.
func (c *Client) RDSInstance(ctx context.Context, scope authz.ResourceScope, id, cluster string) (rdstypes.DBInstance, error) {
	if (cluster == "" && !scope.HasRDSInstance(id)) || (cluster != "" && !scope.HasRDSCluster(cluster)) {
		return rdstypes.DBInstance{}, c.outsideScope()
	}
	out, err := c.rds.DescribeDBInstances(ctx, &rds.DescribeDBInstancesInput{DBInstanceIdentifier: sdkaws.String(id)})
	var notFound *rdstypes.DBInstanceNotFoundFault
	if errors.As(err, &notFound) {
		return rdstypes.DBInstance{}, apierr.Upstream("source %s: DB instance %s not found", c.source.Name, id)
	}
	if err != nil {
		return rdstypes.DBInstance{}, c.apiError("DescribeDBInstances", err)
	}
	for _, instance := range out.DBInstances {
		if !strings.EqualFold(sdkaws.ToString(instance.DBInstanceIdentifier), id) ||
			(cluster != "" && !strings.EqualFold(sdkaws.ToString(instance.DBClusterIdentifier), cluster)) {
			return rdstypes.DBInstance{}, c.outsideScope()
		}
	}
	if len(out.DBInstances) == 0 {
		return rdstypes.DBInstance{}, apierr.Upstream("source %s: DB instance %s not found", c.source.Name, id)
	}
	return out.DBInstances[0], nil
}

// RDSEngineVersion describes an engine version from the RDS catalog, with its valid upgrade
// targets. A version RDS no longer lists returns false.
func (c *Client) RDSEngineVersion(ctx context.Context, engine, version string) (rdstypes.DBEngineVersion, bool, error) {
	out, err := c.rds.DescribeDBEngineVersions(ctx, &rds.DescribeDBEngineVersionsInput{
		Engine:        sdkaws.String(engine),
		EngineVersion: sdkaws.String(version),
		// Deprecated versions are listed too, so a database on one still reports its status.
		IncludeAll: sdkaws.Bool(true),
	})
	if err != nil {
		return rdstypes.DBEngineVersion{}, false, c.apiError("DescribeDBEngineVersions", err)
	}
	for _, v := range out.DBEngineVersions {
		if sdkaws.ToString(v.Engine) == engine && sdkaws.ToString(v.EngineVersion) == version {
			return v, true, nil
		}
	}
	return rdstypes.DBEngineVersion{}, false, nil
}

// lifecycleEngines are the engines DescribeDBMajorEngineVersions accepts; it rejects others,
// such as DocumentDB and Neptune, which DescribeDBClusters also returns.
var lifecycleEngines = map[string]bool{
	"aurora-mysql": true, "aurora-postgresql": true, "mariadb": true, "mysql": true, "postgres": true,
	"custom-sqlserver-ee": true, "custom-sqlserver-se": true, "custom-sqlserver-web": true,
	"db2-ae": true, "db2-ce": true, "db2-se": true,
	"oracle-ee": true, "oracle-ee-cdb": true, "oracle-se2": true, "oracle-se2-cdb": true,
	"sqlserver-ee": true, "sqlserver-se": true, "sqlserver-ex": true, "sqlserver-web": true,
}

// RDSMajorEngineVersion returns the support periods of a major engine version from the RDS
// catalog, or none when RDS has no lifecycle for it.
func (c *Client) RDSMajorEngineVersion(ctx context.Context, engine, major string) ([]rdstypes.SupportedEngineLifecycle, error) {
	if !lifecycleEngines[engine] {
		return nil, nil
	}
	out, err := c.rds.DescribeDBMajorEngineVersions(ctx, &rds.DescribeDBMajorEngineVersionsInput{
		Engine:             sdkaws.String(engine),
		MajorEngineVersion: sdkaws.String(major),
	})
	if err != nil {
		return nil, c.apiError("DescribeDBMajorEngineVersions", err)
	}
	for _, v := range out.DBMajorEngineVersions {
		if sdkaws.ToString(v.Engine) == engine && sdkaws.ToString(v.MajorEngineVersion) == major {
			return v.SupportedEngineLifecycles, nil
		}
	}
	return nil, nil
}

// RDSPendingMaintenance returns the pending maintenance actions of a bound cluster or instance,
// or of a member of the bound cluster named by cluster, by its ARN.
func (c *Client) RDSPendingMaintenance(ctx context.Context, scope authz.ResourceScope, arn, cluster string) ([]rdstypes.PendingMaintenanceAction, error) {
	if !rdsARNInScope(scope, arn, cluster) {
		return nil, c.outsideScope()
	}
	var (
		actions []rdstypes.PendingMaintenanceAction
		marker  *string
	)
	for {
		out, err := c.rds.DescribePendingMaintenanceActions(ctx, &rds.DescribePendingMaintenanceActionsInput{
			ResourceIdentifier: sdkaws.String(arn),
			MaxRecords:         sdkaws.Int32(rdsPage),
			Marker:             marker,
		})
		if err != nil {
			return nil, c.apiError("DescribePendingMaintenanceActions", err)
		}
		for _, resource := range out.PendingMaintenanceActions {
			if sdkaws.ToString(resource.ResourceIdentifier) != arn {
				return nil, c.outsideScope()
			}
			actions = append(actions, resource.PendingMaintenanceActionDetails...)
		}
		if out.Marker == nil {
			return actions, nil
		}
		marker = out.Marker
	}
}

// rdsARNInScope accepts the ARN of a bound cluster or standalone instance, or the instance ARN of
// a member when cluster is bound: the caller read it from an instance that RDSInstance tied to
// that cluster.
func rdsARNInScope(scope authz.ResourceScope, arn, cluster string) bool {
	if _, id, ok := strings.Cut(arn, ":cluster:"); ok {
		return cluster == "" && scope.HasRDSCluster(id)
	}
	_, id, ok := strings.Cut(arn, ":db:")
	switch {
	case !ok || id == "":
		return false
	case cluster != "":
		return scope.HasRDSCluster(cluster)
	}
	return scope.HasRDSInstance(id)
}

// RDSClusterSnapshots reads up to maxSnapshots snapshots of a bound cluster, automated and
// manual, in no particular order, and reports whether more exist.
func (c *Client) RDSClusterSnapshots(ctx context.Context, scope authz.ResourceScope, id string) ([]rdstypes.DBClusterSnapshot, bool, error) {
	if !scope.HasRDSCluster(id) {
		return nil, false, c.outsideScope()
	}
	var (
		snapshots []rdstypes.DBClusterSnapshot
		marker    *string
	)
	for {
		out, err := c.rds.DescribeDBClusterSnapshots(ctx, &rds.DescribeDBClusterSnapshotsInput{
			DBClusterIdentifier: sdkaws.String(id),
			MaxRecords:          sdkaws.Int32(rdsPage),
			Marker:              marker,
		})
		if err != nil {
			return nil, false, c.apiError("DescribeDBClusterSnapshots", err)
		}
		for _, snapshot := range out.DBClusterSnapshots {
			if !strings.EqualFold(sdkaws.ToString(snapshot.DBClusterIdentifier), id) {
				return nil, false, c.outsideScope()
			}
		}
		snapshots = append(snapshots, out.DBClusterSnapshots...)
		if len(snapshots) >= maxSnapshots {
			return snapshots[:maxSnapshots], len(snapshots) > maxSnapshots || out.Marker != nil, nil
		}
		if out.Marker == nil {
			return snapshots, false, nil
		}
		marker = out.Marker
	}
}

// RDSInstanceSnapshots reads up to maxSnapshots snapshots of a bound standalone instance.
func (c *Client) RDSInstanceSnapshots(ctx context.Context, scope authz.ResourceScope, id string) ([]rdstypes.DBSnapshot, bool, error) {
	if !scope.HasRDSInstance(id) {
		return nil, false, c.outsideScope()
	}
	var (
		snapshots []rdstypes.DBSnapshot
		marker    *string
	)
	for {
		out, err := c.rds.DescribeDBSnapshots(ctx, &rds.DescribeDBSnapshotsInput{
			DBInstanceIdentifier: sdkaws.String(id),
			MaxRecords:           sdkaws.Int32(rdsPage),
			Marker:               marker,
		})
		if err != nil {
			return nil, false, c.apiError("DescribeDBSnapshots", err)
		}
		for _, snapshot := range out.DBSnapshots {
			if !strings.EqualFold(sdkaws.ToString(snapshot.DBInstanceIdentifier), id) {
				return nil, false, c.outsideScope()
			}
		}
		snapshots = append(snapshots, out.DBSnapshots...)
		if len(snapshots) >= maxSnapshots {
			return snapshots[:maxSnapshots], len(snapshots) > maxSnapshots || out.Marker != nil, nil
		}
		if out.Marker == nil {
			return snapshots, false, nil
		}
		marker = out.Marker
	}
}

// RDSEvents reads the events of one database in the range, at most maxResourceEvents. cluster
// is the bound cluster of a member instance, empty otherwise.
func (c *Client) RDSEvents(ctx context.Context, scope authz.ResourceScope, sourceType rdstypes.SourceType, id, cluster string, from, to time.Time) ([]rdstypes.Event, bool, error) {
	var bound bool
	switch {
	case sourceType == rdstypes.SourceTypeDbCluster:
		bound = scope.HasRDSCluster(id)
	case sourceType == rdstypes.SourceTypeDbInstance && cluster != "":
		bound = scope.HasRDSCluster(cluster)
	case sourceType == rdstypes.SourceTypeDbInstance:
		bound = scope.HasRDSInstance(id)
	}
	if !bound {
		return nil, false, c.outsideScope()
	}
	var (
		events []rdstypes.Event
		marker *string
	)
	for {
		out, err := c.rds.DescribeEvents(ctx, &rds.DescribeEventsInput{
			SourceType:       sourceType,
			SourceIdentifier: sdkaws.String(id),
			StartTime:        sdkaws.Time(from),
			EndTime:          sdkaws.Time(to),
			MaxRecords:       sdkaws.Int32(rdsPage),
			Marker:           marker,
		})
		if err != nil {
			return nil, false, c.apiError("DescribeEvents", err)
		}
		for _, event := range out.Events {
			if event.SourceType != sourceType || !strings.EqualFold(sdkaws.ToString(event.SourceIdentifier), id) {
				return nil, false, c.outsideScope()
			}
		}
		events = append(events, out.Events...)
		if len(events) >= maxResourceEvents {
			return events[:maxResourceEvents], len(events) > maxResourceEvents || out.Marker != nil, nil
		}
		if out.Marker == nil {
			return events, false, nil
		}
		marker = out.Marker
	}
}
