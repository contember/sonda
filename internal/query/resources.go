package query

import (
	"context"
	"fmt"
	"net/url"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	sdkaws "github.com/aws/aws-sdk-go-v2/aws"
	acmtypes "github.com/aws/aws-sdk-go-v2/service/acm/types"
	ekstypes "github.com/aws/aws-sdk-go-v2/service/eks/types"
	ectypes "github.com/aws/aws-sdk-go-v2/service/elasticache/types"
	rdstypes "github.com/aws/aws-sdk-go-v2/service/rds/types"
	"golang.org/x/sync/errgroup"

	"github.com/contember/sonda/api"
	"github.com/contember/sonda/internal/authz"
	"github.com/contember/sonda/internal/connector/aws"
	"github.com/contember/sonda/internal/policy"
	"github.com/contember/sonda/internal/shape"
)

const (
	defaultResourcesSince = 24 * time.Hour
	// resourceReads bounds the resources read at once in one request.
	resourceReads     = 8
	maxResourceEvents = 50
	newestSnapshots   = 5
	oneDay            = 24 * time.Hour
)

var resourcesUntrusted = []string{
	"data.databases[].pendingMaintenance[].description",
	"data.databases[].members[].pendingMaintenance[].description",
	"data.databases[].instance.pendingMaintenance[].description",
	"data.functions[].stateReason",
	"data.clusters[].health[].message",
	"data.clusters[].addons[].health[].message",
	"data.events[].message",
}

// resourceReader is the part of the AWS connector the resources use case reads through. Every
// method checks its arguments against the scope and its results against the arguments.
type resourceReader interface {
	RDSCluster(ctx context.Context, scope authz.ResourceScope, id string) (rdstypes.DBCluster, error)
	RDSInstance(ctx context.Context, scope authz.ResourceScope, id, cluster string) (rdstypes.DBInstance, error)
	RDSEngineVersion(ctx context.Context, engine, version string) (rdstypes.DBEngineVersion, bool, error)
	RDSMajorEngineVersion(ctx context.Context, engine, major string) ([]rdstypes.SupportedEngineLifecycle, error)
	RDSPendingMaintenance(ctx context.Context, scope authz.ResourceScope, arn, cluster string) ([]rdstypes.PendingMaintenanceAction, error)
	RDSClusterSnapshots(ctx context.Context, scope authz.ResourceScope, id string) ([]rdstypes.DBClusterSnapshot, bool, error)
	RDSInstanceSnapshots(ctx context.Context, scope authz.ResourceScope, id string) ([]rdstypes.DBSnapshot, bool, error)
	RDSEvents(ctx context.Context, scope authz.ResourceScope, sourceType rdstypes.SourceType, id, cluster string, from, to time.Time) ([]rdstypes.Event, bool, error)
	ReplicationGroup(ctx context.Context, scope authz.ResourceScope, id string) (ectypes.ReplicationGroup, error)
	CacheCluster(ctx context.Context, scope authz.ResourceScope, group, id string) (ectypes.CacheCluster, error)
	CacheEngineVersions(ctx context.Context, engine string) ([]string, error)
	CacheUpdateActions(ctx context.Context, scope authz.ResourceScope, group string) ([]ectypes.UpdateAction, error)
	Certificate(ctx context.Context, scope authz.ResourceScope, arn string) (acmtypes.CertificateDetail, error)
	Function(ctx context.Context, scope authz.ResourceScope, name string) (aws.FunctionConfig, error)
	EKSCluster(ctx context.Context, scope authz.ResourceScope, name string) (ekstypes.Cluster, error)
	EKSAddons(ctx context.Context, scope authz.ResourceScope, cluster string) ([]ekstypes.Addon, error)
	EKSAddonVersions(ctx context.Context, addon, kubernetesVersion string) ([]ekstypes.AddonVersionInfo, error)
	EKSClusterVersion(ctx context.Context, version string) (ekstypes.ClusterVersionInformation, bool, error)
}

// Resources returns the configuration state of the service's managed resources and the
// database events in the range.
func (s *Service) Resources(ctx context.Context, identity *authz.Identity, service string, w api.Window) (api.Response[api.Resources], error) {
	scope, err := s.authz.ResourceScope(identity, service, w.Environment)
	if err != nil {
		return api.Response[api.Resources]{}, err
	}
	r, err := policy.Range(w, s.now(), identity.Limits.MaxRange, defaultResourcesSince)
	if err != nil {
		return api.Response[api.Resources]{}, err
	}
	client, ok := s.connectors.AWS[scope.Source().Name]
	if !ok {
		return api.Response[api.Resources]{}, unsupported("resources", scope.Source())
	}
	query := resourcesQuery(scope)
	recordQuery(ctx, scope.Target, query)
	reader := resourceRead{reader: client, scope: scope, redactor: s.redactor, r: r, now: s.now()}
	data, truncated, err := reader.read(ctx)
	if err != nil {
		return api.Response[api.Resources]{}, err
	}
	meta := metaFor(scope.Target, r)
	meta.Sources = []api.SourceRef{resourcesSourceRef(scope, query)}
	meta.Untrusted = resourcesUntrusted
	meta.Truncated = truncated
	return api.Response[api.Resources]{Data: data, Meta: meta}, nil
}

// resourceRead reads every bound resource of one scope, at most resourceReads at once.
type resourceRead struct {
	reader   resourceReader
	scope    authz.ResourceScope
	redactor *shape.Redactor
	r        api.TimeRange
	now      time.Time

	mu        sync.Mutex
	truncated bool
	events    []api.ResourceEvent
}

func (b *resourceRead) read(ctx context.Context) (api.Resources, bool, error) {
	clusters, instances := b.scope.RDSClusters(), b.scope.RDSInstances()
	caches, certificates := b.scope.ElastiCache(), b.scope.Certificates()
	functions, eksClusters := b.scope.Lambdas(), b.scope.EKSClusters()
	data := api.Resources{
		Databases:    make([]api.Database, len(clusters)+len(instances)),
		Caches:       make([]api.Cache, len(caches)),
		Certificates: make([]api.Certificate, len(certificates)),
		Functions:    make([]api.Function, len(functions)),
		Clusters:     make([]api.KubernetesCluster, len(eksClusters)),
	}
	g, ctx := errgroup.WithContext(ctx)
	g.SetLimit(resourceReads)
	for i, id := range clusters {
		g.Go(func() (err error) { data.Databases[i], err = b.cluster(ctx, id); return err })
	}
	for i, id := range instances {
		g.Go(func() (err error) { data.Databases[len(clusters)+i], err = b.instance(ctx, id); return err })
	}
	for i, id := range caches {
		g.Go(func() (err error) { data.Caches[i], err = b.cache(ctx, id); return err })
	}
	for i, arn := range certificates {
		g.Go(func() (err error) { data.Certificates[i], err = b.certificate(ctx, arn); return err })
	}
	for i, name := range functions {
		g.Go(func() (err error) { data.Functions[i], err = b.function(ctx, name); return err })
	}
	for i, name := range eksClusters {
		g.Go(func() (err error) { data.Clusters[i], err = b.kubernetes(ctx, name); return err })
	}
	if err := g.Wait(); err != nil {
		return api.Resources{}, false, err
	}
	sort.SliceStable(b.events, func(i, j int) bool { return b.events[i].Time.After(b.events[j].Time) })
	data.Events = b.events[:min(len(b.events), maxResourceEvents)]
	if data.Events == nil {
		data.Events = []api.ResourceEvent{}
	}
	return data, b.truncated || len(b.events) > maxResourceEvents, nil
}

func (b *resourceRead) markTruncated(cut bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.truncated = b.truncated || cut
}

// addEvents reads the events of one database in the range.
func (b *resourceRead) addEvents(ctx context.Context, sourceType rdstypes.SourceType, id, cluster string) error {
	events, cut, err := b.reader.RDSEvents(ctx, b.scope, sourceType, id, cluster, b.r.From, b.r.To)
	if err != nil {
		return err
	}
	shaped := make([]api.ResourceEvent, 0, len(events))
	for _, e := range events {
		shaped = append(shaped, api.ResourceEvent{
			Time:       sdkaws.ToTime(e.Date),
			Source:     string(sourceType) + "/" + sdkaws.ToString(e.SourceIdentifier),
			Categories: e.EventCategories,
			Message:    b.redactor.Redact(sdkaws.ToString(e.Message)),
		})
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.events = append(b.events, shaped...)
	b.truncated = b.truncated || cut
	return nil
}

func (b *resourceRead) cluster(ctx context.Context, id string) (api.Database, error) {
	cluster, err := b.reader.RDSCluster(ctx, b.scope, id)
	if err != nil {
		return api.Database{}, err
	}
	db := api.Database{
		Identifier:              sdkaws.ToString(cluster.DBClusterIdentifier),
		Kind:                    "cluster",
		Engine:                  sdkaws.ToString(cluster.Engine),
		EngineVersion:           sdkaws.ToString(cluster.EngineVersion),
		Lifecycle:               sdkaws.ToString(cluster.EngineLifecycleSupport),
		Status:                  sdkaws.ToString(cluster.Status),
		BackupRetentionDays:     int(sdkaws.ToInt32(cluster.BackupRetentionPeriod)),
		BackupWindow:            sdkaws.ToString(cluster.PreferredBackupWindow),
		MaintenanceWindow:       sdkaws.ToString(cluster.PreferredMaintenanceWindow),
		LatestRestorableTime:    cluster.LatestRestorableTime,
		EarliestRestorableTime:  cluster.EarliestRestorableTime,
		DeletionProtection:      sdkaws.ToBool(cluster.DeletionProtection),
		AutoMinorVersionUpgrade: sdkaws.ToBool(cluster.AutoMinorVersionUpgrade),
		StorageEncrypted:        sdkaws.ToBool(cluster.StorageEncrypted),
		ParameterGroup:          sdkaws.ToString(cluster.DBClusterParameterGroup),
		PendingModified:         clusterPendingModified(cluster.PendingModifiedValues),
	}
	if err := b.engine(ctx, &db); err != nil {
		return api.Database{}, err
	}
	actions, err := b.reader.RDSPendingMaintenance(ctx, b.scope, sdkaws.ToString(cluster.DBClusterArn), "")
	if err != nil {
		return api.Database{}, err
	}
	db.PendingMaintenance = b.maintenance(actions)
	snapshots, cut, err := b.reader.RDSClusterSnapshots(ctx, b.scope, id)
	if err != nil {
		return api.Database{}, err
	}
	b.markTruncated(cut)
	db.Snapshots = clusterSnapshots(snapshots)
	if err := b.addEvents(ctx, rdstypes.SourceTypeDbCluster, id, ""); err != nil {
		return api.Database{}, err
	}
	for _, member := range cluster.DBClusterMembers {
		memberID := sdkaws.ToString(member.DBInstanceIdentifier)
		instance, err := b.reader.RDSInstance(ctx, b.scope, memberID, id)
		if err != nil {
			return api.Database{}, err
		}
		shaped, err := b.databaseInstance(ctx, instance, id)
		if err != nil {
			return api.Database{}, err
		}
		shaped.Writer = sdkaws.ToBool(member.IsClusterWriter)
		db.Members = append(db.Members, shaped)
		if err := b.addEvents(ctx, rdstypes.SourceTypeDbInstance, memberID, id); err != nil {
			return api.Database{}, err
		}
	}
	sort.SliceStable(db.Members, func(i, j int) bool {
		if db.Members[i].Writer != db.Members[j].Writer {
			return db.Members[i].Writer
		}
		return db.Members[i].Identifier < db.Members[j].Identifier
	})
	return db, nil
}

func (b *resourceRead) instance(ctx context.Context, id string) (api.Database, error) {
	instance, err := b.reader.RDSInstance(ctx, b.scope, id, "")
	if err != nil {
		return api.Database{}, err
	}
	shaped, err := b.databaseInstance(ctx, instance, "")
	if err != nil {
		return api.Database{}, err
	}
	db := api.Database{
		Identifier:              shaped.Identifier,
		Kind:                    "instance",
		Engine:                  sdkaws.ToString(instance.Engine),
		EngineVersion:           sdkaws.ToString(instance.EngineVersion),
		Lifecycle:               sdkaws.ToString(instance.EngineLifecycleSupport),
		Status:                  shaped.Status,
		BackupRetentionDays:     int(sdkaws.ToInt32(instance.BackupRetentionPeriod)),
		BackupWindow:            sdkaws.ToString(instance.PreferredBackupWindow),
		MaintenanceWindow:       sdkaws.ToString(instance.PreferredMaintenanceWindow),
		LatestRestorableTime:    instance.LatestRestorableTime,
		DeletionProtection:      sdkaws.ToBool(instance.DeletionProtection),
		AutoMinorVersionUpgrade: sdkaws.ToBool(instance.AutoMinorVersionUpgrade),
		StorageEncrypted:        sdkaws.ToBool(instance.StorageEncrypted),
		PendingModified:         instancePendingModified(instance.PendingModifiedValues),
		// The actions live on the instance; the database lists them once.
		PendingMaintenance: shaped.PendingMaintenance,
	}
	if len(instance.DBParameterGroups) > 0 {
		db.ParameterGroup = sdkaws.ToString(instance.DBParameterGroups[0].DBParameterGroupName)
	}
	shaped.PendingMaintenance = nil
	db.Instance = &shaped
	if err := b.engine(ctx, &db); err != nil {
		return api.Database{}, err
	}
	snapshots, cut, err := b.reader.RDSInstanceSnapshots(ctx, b.scope, id)
	if err != nil {
		return api.Database{}, err
	}
	b.markTruncated(cut)
	db.Snapshots = instanceSnapshots(snapshots)
	if err := b.addEvents(ctx, rdstypes.SourceTypeDbInstance, id, ""); err != nil {
		return api.Database{}, err
	}
	return db, nil
}

// databaseInstance shapes an instance with its own pending maintenance. cluster is the bound
// cluster of a member, empty for a standalone instance.
func (b *resourceRead) databaseInstance(ctx context.Context, instance rdstypes.DBInstance, cluster string) (api.DatabaseInstance, error) {
	shaped := api.DatabaseInstance{
		Identifier:       sdkaws.ToString(instance.DBInstanceIdentifier),
		Class:            sdkaws.ToString(instance.DBInstanceClass),
		Status:           sdkaws.ToString(instance.DBInstanceStatus),
		AvailabilityZone: sdkaws.ToString(instance.AvailabilityZone),
		MultiAZ:          sdkaws.ToBool(instance.MultiAZ),
		EngineVersion:    sdkaws.ToString(instance.EngineVersion),
		StorageGB:        int(sdkaws.ToInt32(instance.AllocatedStorage)),
		StorageType:      sdkaws.ToString(instance.StorageType),
		CA:               sdkaws.ToString(instance.CACertificateIdentifier),
	}
	if len(instance.DBParameterGroups) > 0 {
		shaped.ParameterApply = sdkaws.ToString(instance.DBParameterGroups[0].ParameterApplyStatus)
	}
	if details := instance.CertificateDetails; details != nil {
		shaped.CAValidTill = details.ValidTill
		if shaped.CA == "" {
			shaped.CA = sdkaws.ToString(details.CAIdentifier)
		}
	}
	actions, err := b.reader.RDSPendingMaintenance(ctx, b.scope, sdkaws.ToString(instance.DBInstanceArn), cluster)
	if err != nil {
		return api.DatabaseInstance{}, err
	}
	shaped.PendingMaintenance = b.maintenance(actions)
	return shaped, nil
}

// engine adds the status of the database's engine version, its upgrade targets and the support
// periods of its major version.
func (b *resourceRead) engine(ctx context.Context, db *api.Database) error {
	db.Upgrades = api.Upgrades{Minor: []string{}, Major: []string{}}
	version, found, err := b.reader.RDSEngineVersion(ctx, db.Engine, db.EngineVersion)
	if err != nil || !found {
		return err
	}
	db.VersionStatus = sdkaws.ToString(version.Status)
	for _, target := range version.ValidUpgradeTarget {
		if sdkaws.ToBool(target.IsMajorVersionUpgrade) {
			db.Upgrades.Major = append(db.Upgrades.Major, sdkaws.ToString(target.EngineVersion))
		} else {
			db.Upgrades.Minor = append(db.Upgrades.Minor, sdkaws.ToString(target.EngineVersion))
		}
	}
	newestFirst(db.Upgrades.Minor)
	newestFirst(db.Upgrades.Major)
	major := sdkaws.ToString(version.MajorEngineVersion)
	if major == "" {
		return nil
	}
	lifecycles, err := b.reader.RDSMajorEngineVersion(ctx, db.Engine, major)
	if err != nil {
		return err
	}
	for _, l := range lifecycles {
		db.Support = append(db.Support, api.SupportPeriod{Name: string(l.LifecycleSupportName), Start: l.LifecycleSupportStartDate, End: l.LifecycleSupportEndDate})
	}
	return nil
}

func (b *resourceRead) maintenance(actions []rdstypes.PendingMaintenanceAction) []api.MaintenanceItem {
	items := make([]api.MaintenanceItem, 0, len(actions))
	for _, a := range actions {
		items = append(items, api.MaintenanceItem{
			Action:           sdkaws.ToString(a.Action),
			Description:      b.redactor.Redact(sdkaws.ToString(a.Description)),
			Status:           sdkaws.ToString(a.OptInStatus),
			AutoAppliedAfter: a.AutoAppliedAfterDate,
			ForcedApplyDate:  a.ForcedApplyDate,
			CurrentApplyDate: a.CurrentApplyDate,
		})
	}
	return items
}

// clusterPendingModified names the changes waiting for the next maintenance window. The master
// password and other credentials are never included.
func clusterPendingModified(p *rdstypes.ClusterPendingModifiedValues) map[string]string {
	if p == nil {
		return nil
	}
	m := map[string]string{}
	setString(m, "engineVersion", p.EngineVersion)
	setString(m, "storageType", p.StorageType)
	setInt(m, "allocatedStorage", p.AllocatedStorage)
	setInt(m, "backupRetentionPeriod", p.BackupRetentionPeriod)
	setInt(m, "iops", p.Iops)
	if p.CertificateDetails != nil {
		setString(m, "caCertificate", p.CertificateDetails.CAIdentifier)
	}
	if len(m) == 0 {
		return nil
	}
	return m
}

func instancePendingModified(p *rdstypes.PendingModifiedValues) map[string]string {
	if p == nil {
		return nil
	}
	m := map[string]string{}
	setString(m, "engineVersion", p.EngineVersion)
	setString(m, "instanceClass", p.DBInstanceClass)
	setString(m, "storageType", p.StorageType)
	setString(m, "caCertificate", p.CACertificateIdentifier)
	setInt(m, "allocatedStorage", p.AllocatedStorage)
	setInt(m, "backupRetentionPeriod", p.BackupRetentionPeriod)
	setInt(m, "iops", p.Iops)
	if p.MultiAZ != nil {
		m["multiAZ"] = strconv.FormatBool(*p.MultiAZ)
	}
	if len(m) == 0 {
		return nil
	}
	return m
}

func setString(m map[string]string, key string, value *string) {
	if v := sdkaws.ToString(value); v != "" {
		m[key] = v
	}
}

func setInt(m map[string]string, key string, value *int32) {
	if value != nil {
		m[key] = strconv.Itoa(int(*value))
	}
}

func clusterSnapshots(snapshots []rdstypes.DBClusterSnapshot) []api.DatabaseSnapshot {
	shaped := make([]api.DatabaseSnapshot, 0, len(snapshots))
	for _, s := range snapshots {
		shaped = append(shaped, api.DatabaseSnapshot{
			Identifier: sdkaws.ToString(s.DBClusterSnapshotIdentifier),
			Type:       sdkaws.ToString(s.SnapshotType),
			Created:    s.SnapshotCreateTime,
			Status:     sdkaws.ToString(s.Status),
			StorageGB:  int(sdkaws.ToInt32(s.AllocatedStorage)),
		})
	}
	return newestSnapshotsOf(shaped)
}

func instanceSnapshots(snapshots []rdstypes.DBSnapshot) []api.DatabaseSnapshot {
	shaped := make([]api.DatabaseSnapshot, 0, len(snapshots))
	for _, s := range snapshots {
		shaped = append(shaped, api.DatabaseSnapshot{
			Identifier: sdkaws.ToString(s.DBSnapshotIdentifier),
			Type:       sdkaws.ToString(s.SnapshotType),
			Created:    s.SnapshotCreateTime,
			Status:     sdkaws.ToString(s.Status),
			StorageGB:  int(sdkaws.ToInt32(s.AllocatedStorage)),
		})
	}
	return newestSnapshotsOf(shaped)
}

// newestSnapshotsOf keeps the newest snapshots; one still being created has no time and comes first.
func newestSnapshotsOf(snapshots []api.DatabaseSnapshot) []api.DatabaseSnapshot {
	sort.SliceStable(snapshots, func(i, j int) bool {
		a, b := snapshots[i].Created, snapshots[j].Created
		if a == nil || b == nil {
			return a == nil && b != nil
		}
		return a.After(*b)
	})
	return snapshots[:min(len(snapshots), newestSnapshots)]
}

func (b *resourceRead) cache(ctx context.Context, id string) (api.Cache, error) {
	group, err := b.reader.ReplicationGroup(ctx, b.scope, id)
	if err != nil {
		return api.Cache{}, err
	}
	cache := api.Cache{
		Identifier:              sdkaws.ToString(group.ReplicationGroupId),
		Engine:                  sdkaws.ToString(group.Engine),
		NewerVersions:           []string{},
		Status:                  sdkaws.ToString(group.Status),
		NodeType:                sdkaws.ToString(group.CacheNodeType),
		Members:                 len(group.MemberClusters),
		MultiAZ:                 group.MultiAZ == ectypes.MultiAZStatusEnabled,
		AutomaticFailover:       group.AutomaticFailover == ectypes.AutomaticFailoverStatusEnabled,
		SnapshotRetentionDays:   int(sdkaws.ToInt32(group.SnapshotRetentionLimit)),
		SnapshotWindow:          sdkaws.ToString(group.SnapshotWindow),
		TransitEncryption:       sdkaws.ToBool(group.TransitEncryptionEnabled),
		AtRestEncryption:        sdkaws.ToBool(group.AtRestEncryptionEnabled),
		AuthToken:               sdkaws.ToBool(group.AuthTokenEnabled),
		AutoMinorVersionUpgrade: sdkaws.ToBool(group.AutoMinorVersionUpgrade),
		PendingUpdates:          []api.MaintenanceItem{},
	}
	if len(group.MemberClusters) > 0 {
		member, err := b.reader.CacheCluster(ctx, b.scope, id, group.MemberClusters[0])
		if err != nil {
			return api.Cache{}, err
		}
		cache.EngineVersion = sdkaws.ToString(member.EngineVersion)
		cache.MaintenanceWindow = sdkaws.ToString(member.PreferredMaintenanceWindow)
		if cache.Engine == "" {
			cache.Engine = sdkaws.ToString(member.Engine)
		}
	}
	if cache.Engine != "" && cache.EngineVersion != "" {
		versions, err := b.reader.CacheEngineVersions(ctx, cache.Engine)
		if err != nil {
			return api.Cache{}, err
		}
		for _, v := range versions {
			// The catalog also lists placeholders such as 6.x; only exact versions compare.
			if numericVersion.MatchString(v) && compareVersions(v, cache.EngineVersion) > 0 {
				cache.NewerVersions = append(cache.NewerVersions, v)
			}
		}
		cache.NewerVersions = slices.Compact(newestFirst(cache.NewerVersions))
	}
	actions, err := b.reader.CacheUpdateActions(ctx, b.scope, id)
	if err != nil {
		return api.Cache{}, err
	}
	for _, a := range actions {
		cache.PendingUpdates = append(cache.PendingUpdates, api.MaintenanceItem{
			Action:      sdkaws.ToString(a.ServiceUpdateName),
			Description: string(a.ServiceUpdateType),
			Status:      string(a.UpdateActionStatus),
			Severity:    string(a.ServiceUpdateSeverity),
			ApplyBy:     a.ServiceUpdateRecommendedApplyByDate,
		})
	}
	return cache, nil
}

func (b *resourceRead) certificate(ctx context.Context, arn string) (api.Certificate, error) {
	cert, err := b.reader.Certificate(ctx, b.scope, arn)
	if err != nil {
		return api.Certificate{}, err
	}
	shaped := api.Certificate{
		ARN:                arn,
		Domain:             sdkaws.ToString(cert.DomainName),
		Names:              cert.SubjectAlternativeNames,
		Status:             string(cert.Status),
		Type:               string(cert.Type),
		NotBefore:          cert.NotBefore,
		NotAfter:           cert.NotAfter,
		RenewalEligibility: string(cert.RenewalEligibility),
		InUseBy:            slices.Sorted(slices.Values(cert.InUseBy)),
		KeyAlgorithm:       string(cert.KeyAlgorithm),
	}
	if shaped.InUseBy == nil {
		shaped.InUseBy = []string{}
	}
	if cert.NotAfter != nil {
		days := int(cert.NotAfter.Sub(b.now) / oneDay)
		shaped.DaysLeft = &days
	}
	if renewal := cert.RenewalSummary; renewal != nil {
		shaped.RenewalStatus = string(renewal.RenewalStatus)
		shaped.RenewalFailure = string(renewal.RenewalStatusReason)
	}
	return shaped, nil
}

func (b *resourceRead) function(ctx context.Context, name string) (api.Function, error) {
	config, err := b.reader.Function(ctx, b.scope, name)
	if err != nil {
		return api.Function{}, err
	}
	fn := api.Function{
		Name:             config.Name,
		Runtime:          config.Runtime,
		Architectures:    config.Architectures,
		PackageType:      config.PackageType,
		Handler:          config.Handler,
		MemoryMB:         config.MemoryMB,
		TimeoutSeconds:   config.TimeoutSeconds,
		State:            config.State,
		StateReason:      b.redactor.Redact(config.StateReason),
		LastUpdateStatus: config.LastUpdateStatus,
		LastModified:     config.LastModified,
		CodeSizeBytes:    config.CodeSize,
		Environment:      config.EnvironmentNames,
		EnvironmentError: config.EnvironmentError,
	}
	for _, layer := range config.Layers {
		fn.Layers = append(fn.Layers, api.Layer{ARN: sdkaws.ToString(layer.Arn), CodeSizeBytes: layer.CodeSize})
	}
	return fn, nil
}

func (b *resourceRead) kubernetes(ctx context.Context, name string) (api.KubernetesCluster, error) {
	cluster, err := b.reader.EKSCluster(ctx, b.scope, name)
	if err != nil {
		return api.KubernetesCluster{}, err
	}
	shaped := api.KubernetesCluster{
		Name:            name,
		Version:         sdkaws.ToString(cluster.Version),
		PlatformVersion: sdkaws.ToString(cluster.PlatformVersion),
		Status:          string(cluster.Status),
		Addons:          []api.Addon{},
	}
	if cluster.UpgradePolicy != nil {
		shaped.SupportType = string(cluster.UpgradePolicy.SupportType)
	}
	if vpc := cluster.ResourcesVpcConfig; vpc != nil {
		shaped.PublicEndpoint, shaped.PrivateEndpoint = vpc.EndpointPublicAccess, vpc.EndpointPrivateAccess
	}
	if cluster.Health != nil {
		for _, issue := range cluster.Health.Issues {
			shaped.Health = append(shaped.Health, api.HealthIssue{Code: string(issue.Code), Message: b.redactor.Redact(sdkaws.ToString(issue.Message))})
		}
	}
	if shaped.Version != "" {
		info, found, err := b.reader.EKSClusterVersion(ctx, shaped.Version)
		if err != nil {
			return api.KubernetesCluster{}, err
		}
		if found {
			shaped.StandardSupportEnd, shaped.ExtendedSupportEnd = info.EndOfStandardSupportDate, info.EndOfExtendedSupportDate
		}
	}
	addons, err := b.reader.EKSAddons(ctx, b.scope, name)
	if err != nil {
		return api.KubernetesCluster{}, err
	}
	for _, addon := range addons {
		shaped.Addons = append(shaped.Addons, api.Addon{
			Name:          sdkaws.ToString(addon.AddonName),
			Version:       sdkaws.ToString(addon.AddonVersion),
			Status:        string(addon.Status),
			NewerVersions: []string{},
		})
		a := &shaped.Addons[len(shaped.Addons)-1]
		if addon.Health != nil {
			for _, issue := range addon.Health.Issues {
				a.Health = append(a.Health, api.HealthIssue{Code: string(issue.Code), Message: b.redactor.Redact(sdkaws.ToString(issue.Message))})
			}
		}
		if shaped.Version == "" {
			continue
		}
		versions, err := b.reader.EKSAddonVersions(ctx, a.Name, shaped.Version)
		if err != nil {
			return api.KubernetesCluster{}, err
		}
		for _, v := range versions {
			version := sdkaws.ToString(v.AddonVersion)
			if compareVersions(version, a.Version) > 0 {
				a.NewerVersions = append(a.NewerVersions, version)
			}
			for _, c := range v.Compatibilities {
				if sdkaws.ToString(c.ClusterVersion) == shaped.Version && c.DefaultVersion {
					a.DefaultVersion = version
				}
			}
		}
		a.NewerVersions = slices.Compact(newestFirst(a.NewerVersions))
	}
	sort.SliceStable(shaped.Addons, func(i, j int) bool { return shaped.Addons[i].Name < shaped.Addons[j].Name })
	return shaped, nil
}

var (
	numericVersion = regexp.MustCompile(`^[0-9]+(\.[0-9]+)*$`)
	versionToken   = regexp.MustCompile(`[0-9]+|[A-Za-z]+`)
)

// compareVersions orders versions such as 16.4, 7.1.0 or v1.19.0-eksbuild.2 by their number and
// word parts: numbers numerically, words as text, and a version that is a prefix of another first.
func compareVersions(a, b string) int {
	ta, tb := versionToken.FindAllString(a, -1), versionToken.FindAllString(b, -1)
	for i := range min(len(ta), len(tb)) {
		if c := compareToken(ta[i], tb[i]); c != 0 {
			return c
		}
	}
	return len(ta) - len(tb)
}

func compareToken(a, b string) int {
	na, errA := strconv.ParseUint(a, 10, 64)
	nb, errB := strconv.ParseUint(b, 10, 64)
	switch {
	case errA == nil && errB == nil:
		if na == nb {
			return 0
		}
		if na < nb {
			return -1
		}
		return 1
	case errA == nil:
		return -1
	case errB == nil:
		return 1
	}
	return strings.Compare(a, b)
}

// newestFirst sorts versions in place, highest first, and returns them.
func newestFirst(versions []string) []string {
	slices.SortStableFunc(versions, func(a, b string) int { return compareVersions(b, a) })
	return versions
}

// resourcesQuery records the bound resources, e.g. "rds_clusters=shop-db lambdas=resize".
func resourcesQuery(scope authz.ResourceScope) string {
	var parts []string
	for _, kind := range []struct {
		name  string
		items []string
	}{
		{"rds_clusters", scope.RDSClusters()}, {"rds_instances", scope.RDSInstances()}, {"elasticache", scope.ElastiCache()},
		{"certificates", scope.Certificates()}, {"lambdas", scope.Lambdas()}, {"eks_clusters", scope.EKSClusters()},
	} {
		if len(kind.items) > 0 {
			parts = append(parts, kind.name+"="+strings.Join(kind.items, ","))
		}
	}
	return strings.Join(parts, " ")
}

// resourcesSourceRef links to the console page of the first database, or else of the first
// bound resource.
func resourcesSourceRef(scope authz.ResourceScope, query string) api.SourceRef {
	region := scope.Source().AWS.Region
	console := fmt.Sprintf("https://%s.console.aws.amazon.com", region)
	q := "?region=" + url.QueryEscape(region)
	ref := api.SourceRef{Kind: "aws", Query: query}
	switch {
	case len(scope.RDSClusters()) > 0:
		ref.URL = console + "/rds/home" + q + "#database:id=" + url.QueryEscape(scope.RDSClusters()[0]) + ";is-cluster=true"
	case len(scope.RDSInstances()) > 0:
		ref.URL = console + "/rds/home" + q + "#database:id=" + url.QueryEscape(scope.RDSInstances()[0]) + ";is-cluster=false"
	case len(scope.ElastiCache()) > 0:
		ref.URL = console + "/elasticache/home" + q + "#/redis/" + url.PathEscape(scope.ElastiCache()[0])
	case len(scope.Certificates()) > 0:
		arn := scope.Certificates()[0]
		ref.URL = console + "/acm/home" + q + "#/certificates/" + url.PathEscape(arn[strings.LastIndex(arn, "/")+1:])
	case len(scope.Lambdas()) > 0:
		ref.URL = console + "/lambda/home" + q + "#/functions/" + url.PathEscape(scope.Lambdas()[0])
	case len(scope.EKSClusters()) > 0:
		ref.URL = console + "/eks/home" + q + "#/clusters/" + url.PathEscape(scope.EKSClusters()[0])
	}
	return ref
}
