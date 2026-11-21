package query

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	sdkaws "github.com/aws/aws-sdk-go-v2/aws"
	acmtypes "github.com/aws/aws-sdk-go-v2/service/acm/types"
	ekstypes "github.com/aws/aws-sdk-go-v2/service/eks/types"
	ectypes "github.com/aws/aws-sdk-go-v2/service/elasticache/types"
	rdstypes "github.com/aws/aws-sdk-go-v2/service/rds/types"

	"github.com/contember/sonda/api"
	"github.com/contember/sonda/internal/authz"
	"github.com/contember/sonda/internal/config"
	"github.com/contember/sonda/internal/connector/aws"
	"github.com/contember/sonda/internal/identities"
	"github.com/contember/sonda/internal/shape"
)

const testCertificateARN = "arn:aws:acm:eu-central-1:123456789012:certificate/0f6a2b1c-3d4e-4f50-8a6b-7c8d9e0f1a2b"

func testResourceScope(t *testing.T, binding string) authz.ResourceScope {
	t.Helper()
	cfg, err := config.Parse([]byte(`
sources:
  aws: { type: aws, region: eu-central-1 }
projects:
  shop:
    services:
      db:
        environments:
          production:
            resources: `+binding+`
`), func(string) (string, bool) { return "", false })
	if err != nil {
		t.Fatal(err)
	}
	identity := &authz.Identity{Name: "agent", Grants: []identities.Grant{
		{Project: "shop", Environment: "production", Capability: api.CapabilityResources},
	}}
	scope, err := authz.New(cfg, nil).ResourceScope(identity, "db", "production")
	if err != nil {
		t.Fatal(err)
	}
	return scope
}

var resourcesNow = time.Date(2026, 11, 20, 12, 0, 0, 0, time.UTC)

func at(hours int) *time.Time {
	t := resourcesNow.Add(time.Duration(hours) * time.Hour)
	return &t
}

// fakeResourceReader serves one Aurora cluster with two members, a Valkey replication group,
// a certificate, a function and an EKS cluster.
type fakeResourceReader struct {
	events int // events per database source
}

func (f fakeResourceReader) RDSCluster(_ context.Context, _ authz.ResourceScope, id string) (rdstypes.DBCluster, error) {
	return rdstypes.DBCluster{
		DBClusterIdentifier: sdkaws.String(id), DBClusterArn: sdkaws.String("arn:aws:rds:eu-central-1:123456789012:cluster:" + id),
		Engine: sdkaws.String("aurora-postgresql"), EngineVersion: sdkaws.String("16.4"), Status: sdkaws.String("available"),
		BackupRetentionPeriod: sdkaws.Int32(7), LatestRestorableTime: at(-1), EngineLifecycleSupport: sdkaws.String("open-source-rds-extended-support"),
		DBClusterMembers: []rdstypes.DBClusterMember{
			{DBInstanceIdentifier: sdkaws.String(id + "-2"), IsClusterWriter: sdkaws.Bool(false)},
			{DBInstanceIdentifier: sdkaws.String(id + "-1"), IsClusterWriter: sdkaws.Bool(true)},
		},
		PendingModifiedValues: &rdstypes.ClusterPendingModifiedValues{EngineVersion: sdkaws.String("16.6"), MasterUserPassword: sdkaws.String("****")},
	}, nil
}

func (f fakeResourceReader) RDSInstance(_ context.Context, _ authz.ResourceScope, id, cluster string) (rdstypes.DBInstance, error) {
	return rdstypes.DBInstance{
		DBInstanceIdentifier: sdkaws.String(id), DBInstanceArn: sdkaws.String("arn:aws:rds:eu-central-1:123456789012:db:" + id),
		DBClusterIdentifier: sdkaws.String(cluster), DBInstanceClass: sdkaws.String("db.r6g.large"), DBInstanceStatus: sdkaws.String("available"),
		CACertificateIdentifier: sdkaws.String("rds-ca-rsa2048-g1"), CertificateDetails: &rdstypes.CertificateDetails{ValidTill: at(24 * 300)},
	}, nil
}

func (f fakeResourceReader) RDSEngineVersion(_ context.Context, engine, version string) (rdstypes.DBEngineVersion, bool, error) {
	return rdstypes.DBEngineVersion{
		Engine: sdkaws.String(engine), EngineVersion: sdkaws.String(version), Status: sdkaws.String("available"), MajorEngineVersion: sdkaws.String("16"),
		ValidUpgradeTarget: []rdstypes.UpgradeTarget{
			{EngineVersion: sdkaws.String("16.6"), IsMajorVersionUpgrade: sdkaws.Bool(false)},
			{EngineVersion: sdkaws.String("17.4"), IsMajorVersionUpgrade: sdkaws.Bool(true)},
			{EngineVersion: sdkaws.String("16.10"), IsMajorVersionUpgrade: sdkaws.Bool(false)},
		},
	}, true, nil
}

func (f fakeResourceReader) RDSMajorEngineVersion(context.Context, string, string) ([]rdstypes.SupportedEngineLifecycle, error) {
	return []rdstypes.SupportedEngineLifecycle{{LifecycleSupportName: "open-source-rds-standard-support", LifecycleSupportEndDate: at(24 * 700)}}, nil
}

func (f fakeResourceReader) RDSPendingMaintenance(_ context.Context, _ authz.ResourceScope, arn, _ string) ([]rdstypes.PendingMaintenanceAction, error) {
	if !strings.HasSuffix(arn, ":cluster:shop-db") {
		return nil, nil
	}
	return []rdstypes.PendingMaintenanceAction{{Action: sdkaws.String("system-update"), Description: sdkaws.String("Upgrade, password=hunter2"), AutoAppliedAfterDate: at(48)}}, nil
}

func (f fakeResourceReader) RDSClusterSnapshots(_ context.Context, _ authz.ResourceScope, id string) ([]rdstypes.DBClusterSnapshot, bool, error) {
	var snapshots []rdstypes.DBClusterSnapshot
	for i := range 7 {
		snapshots = append(snapshots, rdstypes.DBClusterSnapshot{DBClusterSnapshotIdentifier: sdkaws.String(fmt.Sprintf("rds:%s-%d", id, i)), SnapshotType: sdkaws.String("automated"), SnapshotCreateTime: at(-24 * i), Status: sdkaws.String("available")})
	}
	return snapshots, false, nil
}

func (f fakeResourceReader) RDSInstanceSnapshots(context.Context, authz.ResourceScope, string) ([]rdstypes.DBSnapshot, bool, error) {
	return nil, false, nil
}

func (f fakeResourceReader) RDSEvents(_ context.Context, _ authz.ResourceScope, sourceType rdstypes.SourceType, id, _ string, _, _ time.Time) ([]rdstypes.Event, bool, error) {
	var events []rdstypes.Event
	for i := range f.events {
		events = append(events, rdstypes.Event{Date: at(-i), SourceType: sourceType, SourceIdentifier: sdkaws.String(id), Message: sdkaws.String("event " + id)})
	}
	return events, false, nil
}

func (f fakeResourceReader) ReplicationGroup(_ context.Context, _ authz.ResourceScope, id string) (ectypes.ReplicationGroup, error) {
	return ectypes.ReplicationGroup{ReplicationGroupId: sdkaws.String(id), Engine: sdkaws.String("valkey"), MemberClusters: []string{id + "-001", id + "-002"},
		MultiAZ: ectypes.MultiAZStatusEnabled, SnapshotRetentionLimit: sdkaws.Int32(1)}, nil
}

func (f fakeResourceReader) CacheCluster(_ context.Context, _ authz.ResourceScope, group, id string) (ectypes.CacheCluster, error) {
	return ectypes.CacheCluster{CacheClusterId: sdkaws.String(id), ReplicationGroupId: sdkaws.String(group), EngineVersion: sdkaws.String("7.2.4")}, nil
}

func (f fakeResourceReader) CacheEngineVersions(context.Context, string) ([]string, error) {
	return []string{"7.2", "7.2.4", "8.0", "7.x", "8.1", "6.2"}, nil
}

func (f fakeResourceReader) CacheUpdateActions(context.Context, authz.ResourceScope, string) ([]ectypes.UpdateAction, error) {
	return []ectypes.UpdateAction{{ServiceUpdateName: sdkaws.String("elc-2026-001"), ServiceUpdateSeverity: ectypes.ServiceUpdateSeverityImportant, UpdateActionStatus: ectypes.UpdateActionStatusNotApplied}}, nil
}

func (f fakeResourceReader) Certificate(_ context.Context, _ authz.ResourceScope, arn string) (acmtypes.CertificateDetail, error) {
	return acmtypes.CertificateDetail{CertificateArn: sdkaws.String(arn), DomainName: sdkaws.String("shop.example.com"), Status: acmtypes.CertificateStatusIssued,
		NotAfter: at(24*20 + 5), RenewalEligibility: acmtypes.RenewalEligibilityEligible, InUseBy: []string{"arn:b", "arn:a"}}, nil
}

func (f fakeResourceReader) Function(_ context.Context, _ authz.ResourceScope, name string) (aws.FunctionConfig, error) {
	return aws.FunctionConfig{Name: name, Runtime: "nodejs18.x", EnvironmentNames: []string{"API_KEY"}}, nil
}

func (f fakeResourceReader) EKSCluster(_ context.Context, _ authz.ResourceScope, name string) (ekstypes.Cluster, error) {
	return ekstypes.Cluster{Name: sdkaws.String(name), Version: sdkaws.String("1.31"), Status: ekstypes.ClusterStatusActive,
		UpgradePolicy: &ekstypes.UpgradePolicyResponse{SupportType: ekstypes.SupportTypeExtended}}, nil
}

func (f fakeResourceReader) EKSAddons(_ context.Context, _ authz.ResourceScope, cluster string) ([]ekstypes.Addon, error) {
	return []ekstypes.Addon{{AddonName: sdkaws.String("vpc-cni"), ClusterName: sdkaws.String(cluster), AddonVersion: sdkaws.String("v1.19.0-eksbuild.2"), Status: ekstypes.AddonStatusActive}}, nil
}

func (f fakeResourceReader) EKSAddonVersions(context.Context, string, string) ([]ekstypes.AddonVersionInfo, error) {
	compatible := func(def bool) []ekstypes.Compatibility {
		return []ekstypes.Compatibility{{ClusterVersion: sdkaws.String("1.31"), DefaultVersion: def}}
	}
	return []ekstypes.AddonVersionInfo{
		{AddonVersion: sdkaws.String("v1.19.0-eksbuild.10"), Compatibilities: compatible(false)},
		{AddonVersion: sdkaws.String("v1.19.0-eksbuild.1"), Compatibilities: compatible(false)},
		{AddonVersion: sdkaws.String("v1.20.1-eksbuild.1"), Compatibilities: compatible(true)},
	}, nil
}

func (f fakeResourceReader) EKSClusterVersion(context.Context, string) (ekstypes.ClusterVersionInformation, bool, error) {
	return ekstypes.ClusterVersionInformation{EndOfStandardSupportDate: at(24 * 10)}, true, nil
}

func readResources(t *testing.T, reader resourceReader, binding string) (api.Resources, bool) {
	t.Helper()
	redactor, err := shape.NewRedactor(nil)
	if err != nil {
		t.Fatal(err)
	}
	read := &resourceRead{reader: reader, scope: testResourceScope(t, binding), redactor: redactor,
		r: api.TimeRange{From: resourcesNow.Add(-24 * time.Hour), To: resourcesNow}, now: resourcesNow}
	data, truncated, err := read.read(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return data, truncated
}

func TestResourcesDatabase(t *testing.T) {
	data, truncated := readResources(t, fakeResourceReader{events: 1}, `{ source: aws, rds_clusters: [shop-db] }`)
	if truncated || len(data.Databases) != 1 {
		t.Fatalf("databases = %+v, truncated = %v", data.Databases, truncated)
	}
	db := data.Databases[0]
	if db.Kind != "cluster" || db.EngineVersion != "16.4" || db.VersionStatus != "available" || db.BackupRetentionDays != 7 {
		t.Errorf("database = %+v", db)
	}
	if !slices.Equal(db.Upgrades.Minor, []string{"16.10", "16.6"}) || !slices.Equal(db.Upgrades.Major, []string{"17.4"}) {
		t.Errorf("upgrades = %+v", db.Upgrades)
	}
	if len(db.Support) != 1 || db.Support[0].Name != "open-source-rds-standard-support" {
		t.Errorf("support = %+v", db.Support)
	}
	if len(db.Members) != 2 || db.Members[0].Identifier != "shop-db-1" || !db.Members[0].Writer || db.Members[1].Writer || db.Members[0].CAValidTill == nil {
		t.Errorf("members = %+v", db.Members)
	}
	if len(db.PendingMaintenance) != 1 || strings.Contains(db.PendingMaintenance[0].Description, "hunter2") {
		t.Errorf("pending maintenance = %+v", db.PendingMaintenance)
	}
	if db.PendingModified["engineVersion"] != "16.6" || len(db.PendingModified) != 1 {
		t.Errorf("pending modified = %v (the master password must never appear)", db.PendingModified)
	}
	if len(db.Snapshots) != newestSnapshots || db.Snapshots[0].Identifier != "rds:shop-db-0" {
		t.Errorf("snapshots = %+v", db.Snapshots)
	}
	if len(data.Events) != 3 || data.Events[0].Source != "db-cluster/shop-db" && data.Events[0].Source != "db-instance/shop-db-1" {
		t.Errorf("events = %+v", data.Events)
	}
	if data.Caches == nil || data.Functions == nil || data.Certificates == nil || data.Clusters == nil {
		t.Errorf("unbound kinds must be empty lists: %+v", data)
	}
}

func TestResourcesEventsCut(t *testing.T) {
	data, truncated := readResources(t, fakeResourceReader{events: 30}, `{ source: aws, rds_clusters: [shop-db] }`)
	if len(data.Events) != maxResourceEvents || !truncated {
		t.Errorf("events = %d, truncated = %v", len(data.Events), truncated)
	}
	for i := 1; i < len(data.Events); i++ {
		if data.Events[i].Time.After(data.Events[i-1].Time) {
			t.Fatalf("events are not newest first at %d", i)
		}
	}
}

func TestResourcesOtherKinds(t *testing.T) {
	data, _ := readResources(t, fakeResourceReader{}, `{ source: aws, elasticache: [shop-cache], certificates: [`+testCertificateARN+`], lambdas: [shop-resize], eks_clusters: [shop-prod] }`)
	cache := data.Caches[0]
	if cache.EngineVersion != "7.2.4" || !slices.Equal(cache.NewerVersions, []string{"8.1", "8.0"}) || cache.Members != 2 || !cache.MultiAZ {
		t.Errorf("cache = %+v", cache)
	}
	if len(cache.PendingUpdates) != 1 || cache.PendingUpdates[0].Severity != "important" {
		t.Errorf("pending updates = %+v", cache.PendingUpdates)
	}
	cert := data.Certificates[0]
	if cert.DaysLeft == nil || *cert.DaysLeft != 20 || !slices.Equal(cert.InUseBy, []string{"arn:a", "arn:b"}) {
		t.Errorf("certificate = %+v", cert)
	}
	if fn := data.Functions[0]; fn.Runtime != "nodejs18.x" || !slices.Equal(fn.Environment, []string{"API_KEY"}) {
		t.Errorf("function = %+v", fn)
	}
	cluster := data.Clusters[0]
	if cluster.SupportType != "EXTENDED" || cluster.StandardSupportEnd == nil || len(cluster.Addons) != 1 {
		t.Fatalf("cluster = %+v", cluster)
	}
	addon := cluster.Addons[0]
	if !slices.Equal(addon.NewerVersions, []string{"v1.20.1-eksbuild.1", "v1.19.0-eksbuild.10"}) || addon.DefaultVersion != "v1.20.1-eksbuild.1" {
		t.Errorf("addon = %+v", addon)
	}
}

func TestCompareVersions(t *testing.T) {
	for _, tt := range []struct {
		a, b string
		want int
	}{
		{"16.10", "16.6", 1},
		{"7.2", "7.2.4", -1},
		{"8.0", "7.2.4", 1},
		{"v1.19.0-eksbuild.10", "v1.19.0-eksbuild.2", 1},
		{"v1.20.0-eksbuild.1", "v1.19.0-eksbuild.10", 1},
		{"5.7.mysql_aurora.2.12.1", "5.7.mysql_aurora.2.11.4", 1},
		{"16.4", "16.4", 0},
	} {
		got := compareVersions(tt.a, tt.b)
		if (got > 0) != (tt.want > 0) || (got < 0) != (tt.want < 0) {
			t.Errorf("compareVersions(%q, %q) = %d, want sign of %d", tt.a, tt.b, got, tt.want)
		}
	}
}

func TestResourcesSourceRef(t *testing.T) {
	ref := resourcesSourceRef(testResourceScope(t, `{ source: aws, lambdas: [shop-resize], rds_instances: [shop-legacy] }`), "q")
	if ref.URL != "https://eu-central-1.console.aws.amazon.com/rds/home?region=eu-central-1#database:id=shop-legacy;is-cluster=false" {
		t.Errorf("url = %s", ref.URL)
	}
}
