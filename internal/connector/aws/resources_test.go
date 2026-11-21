package aws

import (
	"context"
	"encoding/json"
	"slices"
	"strings"
	"testing"
	"time"

	sdkaws "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/acm"
	acmtypes "github.com/aws/aws-sdk-go-v2/service/acm/types"
	"github.com/aws/aws-sdk-go-v2/service/eks"
	ekstypes "github.com/aws/aws-sdk-go-v2/service/eks/types"
	"github.com/aws/aws-sdk-go-v2/service/elasticache"
	ectypes "github.com/aws/aws-sdk-go-v2/service/elasticache/types"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
	lambdatypes "github.com/aws/aws-sdk-go-v2/service/lambda/types"
	"github.com/aws/aws-sdk-go-v2/service/rds"
	rdstypes "github.com/aws/aws-sdk-go-v2/service/rds/types"

	"github.com/contember/sonda/api"
	"github.com/contember/sonda/internal/apierr"
	"github.com/contember/sonda/internal/authz"
	"github.com/contember/sonda/internal/config"
	"github.com/contember/sonda/internal/identities"
)

const certificateARN = "arn:aws:acm:eu-central-1:123456789012:certificate/0f6a2b1c-3d4e-4f50-8a6b-7c8d9e0f1a2b"

func resourceScope(t *testing.T) (*config.Config, authz.ResourceScope) {
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
            resources:
              source: aws
              rds_clusters: [shop-db]
              rds_instances: [shop-legacy]
              elasticache: [shop-cache]
              certificates: [`+certificateARN+`]
              lambdas: [shop-resize]
              eks_clusters: [shop-prod]
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
	return cfg, scope
}

// fakeResources answers the RDS, ElastiCache, ACM, Lambda and EKS calls with fixed outputs.
type fakeResources struct {
	clusters       []rdstypes.DBCluster
	clusterErr     error
	instances      []rdstypes.DBInstance
	maintenance    []rdstypes.ResourcePendingMaintenanceActions
	events         []rdstypes.Event
	groups         []ectypes.ReplicationGroup
	cacheClusters  []ectypes.CacheCluster
	certificate    *acmtypes.CertificateDetail
	function       *lambda.GetFunctionConfigurationOutput
	cluster        *ekstypes.Cluster
	addons         map[string]*ekstypes.Addon
	maintenanceARN []string
	clusterSnaps   []rdstypes.DBClusterSnapshot
	instanceSnaps  []rdstypes.DBSnapshot
	updateActions  []ectypes.UpdateAction
	majorCalls     int
}

func (f *fakeResources) DescribeDBClusters(context.Context, *rds.DescribeDBClustersInput, ...func(*rds.Options)) (*rds.DescribeDBClustersOutput, error) {
	return &rds.DescribeDBClustersOutput{DBClusters: f.clusters}, f.clusterErr
}

func (f *fakeResources) DescribeDBInstances(context.Context, *rds.DescribeDBInstancesInput, ...func(*rds.Options)) (*rds.DescribeDBInstancesOutput, error) {
	return &rds.DescribeDBInstancesOutput{DBInstances: f.instances}, nil
}

func (f *fakeResources) DescribeDBEngineVersions(context.Context, *rds.DescribeDBEngineVersionsInput, ...func(*rds.Options)) (*rds.DescribeDBEngineVersionsOutput, error) {
	return &rds.DescribeDBEngineVersionsOutput{}, nil
}

func (f *fakeResources) DescribeDBMajorEngineVersions(context.Context, *rds.DescribeDBMajorEngineVersionsInput, ...func(*rds.Options)) (*rds.DescribeDBMajorEngineVersionsOutput, error) {
	f.majorCalls++
	return &rds.DescribeDBMajorEngineVersionsOutput{}, nil
}

func (f *fakeResources) DescribePendingMaintenanceActions(_ context.Context, in *rds.DescribePendingMaintenanceActionsInput, _ ...func(*rds.Options)) (*rds.DescribePendingMaintenanceActionsOutput, error) {
	f.maintenanceARN = append(f.maintenanceARN, sdkaws.ToString(in.ResourceIdentifier))
	return &rds.DescribePendingMaintenanceActionsOutput{PendingMaintenanceActions: f.maintenance}, nil
}

func (f *fakeResources) DescribeDBClusterSnapshots(context.Context, *rds.DescribeDBClusterSnapshotsInput, ...func(*rds.Options)) (*rds.DescribeDBClusterSnapshotsOutput, error) {
	return &rds.DescribeDBClusterSnapshotsOutput{DBClusterSnapshots: f.clusterSnaps}, nil
}

func (f *fakeResources) DescribeDBSnapshots(context.Context, *rds.DescribeDBSnapshotsInput, ...func(*rds.Options)) (*rds.DescribeDBSnapshotsOutput, error) {
	return &rds.DescribeDBSnapshotsOutput{DBSnapshots: f.instanceSnaps}, nil
}

func (f *fakeResources) DescribeEvents(context.Context, *rds.DescribeEventsInput, ...func(*rds.Options)) (*rds.DescribeEventsOutput, error) {
	return &rds.DescribeEventsOutput{Events: f.events}, nil
}

func (f *fakeResources) DescribeReplicationGroups(context.Context, *elasticache.DescribeReplicationGroupsInput, ...func(*elasticache.Options)) (*elasticache.DescribeReplicationGroupsOutput, error) {
	return &elasticache.DescribeReplicationGroupsOutput{ReplicationGroups: f.groups}, nil
}

func (f *fakeResources) DescribeCacheClusters(context.Context, *elasticache.DescribeCacheClustersInput, ...func(*elasticache.Options)) (*elasticache.DescribeCacheClustersOutput, error) {
	return &elasticache.DescribeCacheClustersOutput{CacheClusters: f.cacheClusters}, nil
}

func (f *fakeResources) DescribeCacheEngineVersions(context.Context, *elasticache.DescribeCacheEngineVersionsInput, ...func(*elasticache.Options)) (*elasticache.DescribeCacheEngineVersionsOutput, error) {
	return &elasticache.DescribeCacheEngineVersionsOutput{}, nil
}

func (f *fakeResources) DescribeUpdateActions(context.Context, *elasticache.DescribeUpdateActionsInput, ...func(*elasticache.Options)) (*elasticache.DescribeUpdateActionsOutput, error) {
	return &elasticache.DescribeUpdateActionsOutput{UpdateActions: f.updateActions}, nil
}

func (f *fakeResources) DescribeCertificate(context.Context, *acm.DescribeCertificateInput, ...func(*acm.Options)) (*acm.DescribeCertificateOutput, error) {
	return &acm.DescribeCertificateOutput{Certificate: f.certificate}, nil
}

func (f *fakeResources) GetFunctionConfiguration(context.Context, *lambda.GetFunctionConfigurationInput, ...func(*lambda.Options)) (*lambda.GetFunctionConfigurationOutput, error) {
	return f.function, nil
}

func (f *fakeResources) DescribeCluster(context.Context, *eks.DescribeClusterInput, ...func(*eks.Options)) (*eks.DescribeClusterOutput, error) {
	return &eks.DescribeClusterOutput{Cluster: f.cluster}, nil
}

func (f *fakeResources) ListAddons(context.Context, *eks.ListAddonsInput, ...func(*eks.Options)) (*eks.ListAddonsOutput, error) {
	return &eks.ListAddonsOutput{Addons: slices.Sorted(func(yield func(string) bool) {
		for name := range f.addons {
			if !yield(name) {
				return
			}
		}
	})}, nil
}

func (f *fakeResources) DescribeAddon(_ context.Context, in *eks.DescribeAddonInput, _ ...func(*eks.Options)) (*eks.DescribeAddonOutput, error) {
	return &eks.DescribeAddonOutput{Addon: f.addons[sdkaws.ToString(in.AddonName)]}, nil
}

func (f *fakeResources) DescribeAddonVersions(context.Context, *eks.DescribeAddonVersionsInput, ...func(*eks.Options)) (*eks.DescribeAddonVersionsOutput, error) {
	return &eks.DescribeAddonVersionsOutput{}, nil
}

func (f *fakeResources) DescribeClusterVersions(context.Context, *eks.DescribeClusterVersionsInput, ...func(*eks.Options)) (*eks.DescribeClusterVersionsOutput, error) {
	return &eks.DescribeClusterVersionsOutput{}, nil
}

func resourceClient(cfg *config.Config, fake *fakeResources) *Client {
	c := newClient(cfg.Sources["aws"], nil, nil, &fakeIdentity{})
	c.rds, c.cache, c.acm, c.lambda, c.eks = fake, fake, fake, fake, fake
	return c
}

func wantCode(t *testing.T, what string, err error, code api.ErrorCode) {
	t.Helper()
	if apiErr, ok := apierr.As(err); !ok || apiErr.Code != code {
		t.Errorf("%s: error = %v, want %s", what, err, code)
	}
}

func TestFunctionDropsEnvironmentValues(t *testing.T) {
	cfg, scope := resourceScope(t)
	fake := &fakeResources{function: &lambda.GetFunctionConfigurationOutput{
		FunctionName: sdkaws.String("shop-resize"),
		Runtime:      lambdatypes.RuntimeNodejs20x,
		Environment: &lambdatypes.EnvironmentResponse{
			Variables: map[string]string{"DATABASE_URL": "postgres://app:s3cr3t-value@db/shop", "API_KEY": "sk_live_secret-value"},
			Error:     &lambdatypes.EnvironmentError{ErrorCode: sdkaws.String("KMSAccessDenied"), Message: sdkaws.String("key arn:aws:kms:secret-key-detail")},
		},
	}}
	fn, err := resourceClient(cfg, fake).Function(context.Background(), scope, "shop-resize")
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(fn.EnvironmentNames, []string{"API_KEY", "DATABASE_URL"}) || !fn.EnvironmentError || fn.Runtime != "nodejs20.x" {
		t.Errorf("function = %+v", fn)
	}
	data, err := json.Marshal(fn)
	if err != nil {
		t.Fatal(err)
	}
	for _, value := range []string{"s3cr3t-value", "secret-value", "secret-key-detail", "KMSAccessDenied"} {
		if strings.Contains(string(data), value) {
			t.Errorf("configuration leaks %q: %s", value, data)
		}
	}
}

func TestFunctionScope(t *testing.T) {
	cfg, scope := resourceScope(t)
	fake := &fakeResources{function: &lambda.GetFunctionConfigurationOutput{FunctionName: sdkaws.String("other")}}
	_, err := resourceClient(cfg, fake).Function(context.Background(), scope, "shop-resize")
	wantCode(t, "another function", err, api.CodeInternal)
	_, err = resourceClient(cfg, fake).Function(context.Background(), scope, "other")
	wantCode(t, "unbound function", err, api.CodeInternal)
}

func TestRDSClusterScope(t *testing.T) {
	cfg, scope := resourceScope(t)
	db := rdstypes.DBCluster{DBClusterIdentifier: sdkaws.String("shop-db")}
	cluster, err := resourceClient(cfg, &fakeResources{clusters: []rdstypes.DBCluster{db}}).RDSCluster(context.Background(), scope, "shop-db")
	if err != nil || sdkaws.ToString(cluster.DBClusterIdentifier) != "shop-db" {
		t.Errorf("cluster = %+v, err = %v", cluster, err)
	}
	_, err = resourceClient(cfg, &fakeResources{clusters: []rdstypes.DBCluster{db}}).RDSCluster(context.Background(), scope, "other-db")
	wantCode(t, "unbound cluster", err, api.CodeInternal)
	other := rdstypes.DBCluster{DBClusterIdentifier: sdkaws.String("other-db")}
	_, err = resourceClient(cfg, &fakeResources{clusters: []rdstypes.DBCluster{other}}).RDSCluster(context.Background(), scope, "shop-db")
	wantCode(t, "another cluster returned", err, api.CodeInternal)
	_, err = resourceClient(cfg, &fakeResources{clusterErr: &rdstypes.DBClusterNotFoundFault{}}).RDSCluster(context.Background(), scope, "shop-db")
	wantCode(t, "missing cluster", err, api.CodeUpstreamError)
}

func TestRDSInstanceMemberOfBoundCluster(t *testing.T) {
	cfg, scope := resourceScope(t)
	member := rdstypes.DBInstance{DBInstanceIdentifier: sdkaws.String("shop-db-1"), DBClusterIdentifier: sdkaws.String("shop-db")}
	if _, err := resourceClient(cfg, &fakeResources{instances: []rdstypes.DBInstance{member}}).RDSInstance(context.Background(), scope, "shop-db-1", "shop-db"); err != nil {
		t.Errorf("member: %v", err)
	}
	foreign := rdstypes.DBInstance{DBInstanceIdentifier: sdkaws.String("shop-db-1"), DBClusterIdentifier: sdkaws.String("other-db")}
	_, err := resourceClient(cfg, &fakeResources{instances: []rdstypes.DBInstance{foreign}}).RDSInstance(context.Background(), scope, "shop-db-1", "shop-db")
	wantCode(t, "member of another cluster", err, api.CodeInternal)
	_, err = resourceClient(cfg, &fakeResources{instances: []rdstypes.DBInstance{member}}).RDSInstance(context.Background(), scope, "shop-db-1", "")
	wantCode(t, "unbound standalone instance", err, api.CodeInternal)
}

func TestRDSPendingMaintenanceScope(t *testing.T) {
	cfg, scope := resourceScope(t)
	clusterARN := "arn:aws:rds:eu-central-1:123456789012:cluster:shop-db"
	fake := &fakeResources{maintenance: []rdstypes.ResourcePendingMaintenanceActions{{
		ResourceIdentifier:              sdkaws.String(clusterARN),
		PendingMaintenanceActionDetails: []rdstypes.PendingMaintenanceAction{{Action: sdkaws.String("system-update")}},
	}}}
	actions, err := resourceClient(cfg, fake).RDSPendingMaintenance(context.Background(), scope, clusterARN, "")
	if err != nil || len(actions) != 1 {
		t.Errorf("actions = %v, err = %v", actions, err)
	}
	for _, tt := range []struct{ arn, cluster string }{
		{"arn:aws:rds:eu-central-1:123456789012:cluster:other-db", ""},
		{"arn:aws:rds:eu-central-1:123456789012:db:other", ""},
		{"arn:aws:rds:eu-central-1:123456789012:db:shop-db-1", "other-db"},
		{clusterARN, "shop-db"},
	} {
		_, err := resourceClient(cfg, fake).RDSPendingMaintenance(context.Background(), scope, tt.arn, tt.cluster)
		wantCode(t, tt.arn+" in "+tt.cluster, err, api.CodeInternal)
	}
	// A response for another resource than requested fails the request.
	_, err = resourceClient(cfg, fake).RDSPendingMaintenance(context.Background(), scope, "arn:aws:rds:eu-central-1:123456789012:db:shop-legacy", "")
	wantCode(t, "response for another resource", err, api.CodeInternal)
}

func TestRDSEventsScope(t *testing.T) {
	cfg, scope := resourceScope(t)
	from, to := time.Now().Add(-time.Hour), time.Now()
	fake := &fakeResources{events: []rdstypes.Event{{SourceType: rdstypes.SourceTypeDbCluster, SourceIdentifier: sdkaws.String("shop-db")}}}
	if events, _, err := resourceClient(cfg, fake).RDSEvents(context.Background(), scope, rdstypes.SourceTypeDbCluster, "shop-db", "", from, to); err != nil || len(events) != 1 {
		t.Errorf("events = %v, err = %v", events, err)
	}
	_, _, err := resourceClient(cfg, fake).RDSEvents(context.Background(), scope, rdstypes.SourceTypeDbInstance, "shop-legacy", "", from, to)
	wantCode(t, "event of another source", err, api.CodeInternal)
	_, _, err = resourceClient(cfg, fake).RDSEvents(context.Background(), scope, rdstypes.SourceTypeDbCluster, "other-db", "", from, to)
	wantCode(t, "unbound cluster", err, api.CodeInternal)
}

func TestCacheClusterOfBoundGroup(t *testing.T) {
	cfg, scope := resourceScope(t)
	member := ectypes.CacheCluster{CacheClusterId: sdkaws.String("shop-cache-001"), ReplicationGroupId: sdkaws.String("shop-cache")}
	if _, err := resourceClient(cfg, &fakeResources{cacheClusters: []ectypes.CacheCluster{member}}).CacheCluster(context.Background(), scope, "shop-cache", "shop-cache-001"); err != nil {
		t.Errorf("member: %v", err)
	}
	foreign := ectypes.CacheCluster{CacheClusterId: sdkaws.String("shop-cache-001"), ReplicationGroupId: sdkaws.String("other")}
	_, err := resourceClient(cfg, &fakeResources{cacheClusters: []ectypes.CacheCluster{foreign}}).CacheCluster(context.Background(), scope, "shop-cache", "shop-cache-001")
	wantCode(t, "member of another group", err, api.CodeInternal)
	group := ectypes.ReplicationGroup{ReplicationGroupId: sdkaws.String("other")}
	_, err = resourceClient(cfg, &fakeResources{groups: []ectypes.ReplicationGroup{group}}).ReplicationGroup(context.Background(), scope, "shop-cache")
	wantCode(t, "another group returned", err, api.CodeInternal)
	_, err = resourceClient(cfg, &fakeResources{}).ReplicationGroup(context.Background(), scope, "shop-cache")
	wantCode(t, "missing group", err, api.CodeUpstreamError)
}

func TestCertificateScope(t *testing.T) {
	cfg, scope := resourceScope(t)
	other := strings.Replace(certificateARN, "0f6a", "aaaa", 1)
	_, err := resourceClient(cfg, &fakeResources{certificate: &acmtypes.CertificateDetail{CertificateArn: sdkaws.String(other)}}).Certificate(context.Background(), scope, certificateARN)
	wantCode(t, "another certificate returned", err, api.CodeInternal)
	_, err = resourceClient(cfg, &fakeResources{}).Certificate(context.Background(), scope, other)
	wantCode(t, "unbound certificate", err, api.CodeInternal)
	_, err = resourceClient(cfg, &fakeResources{}).Certificate(context.Background(), scope, certificateARN)
	wantCode(t, "missing certificate", err, api.CodeUpstreamError)
}

func TestEKSAddonsScope(t *testing.T) {
	cfg, scope := resourceScope(t)
	fake := &fakeResources{addons: map[string]*ekstypes.Addon{
		"vpc-cni": {AddonName: sdkaws.String("vpc-cni"), ClusterName: sdkaws.String("shop-prod"), AddonVersion: sdkaws.String("v1.19.0-eksbuild.1")},
	}}
	addons, truncated, err := resourceClient(cfg, fake).EKSAddons(context.Background(), scope, "shop-prod")
	if err != nil || len(addons) != 1 || truncated {
		t.Errorf("addons = %v, err = %v", addons, err)
	}
	fake.addons["coredns"] = &ekstypes.Addon{AddonName: sdkaws.String("coredns"), ClusterName: sdkaws.String("other")}
	_, _, err = resourceClient(cfg, fake).EKSAddons(context.Background(), scope, "shop-prod")
	wantCode(t, "add-on of another cluster", err, api.CodeInternal)
	_, err = resourceClient(cfg, &fakeResources{cluster: &ekstypes.Cluster{Name: sdkaws.String("other")}}).EKSCluster(context.Background(), scope, "shop-prod")
	wantCode(t, "another cluster returned", err, api.CodeInternal)
	_, err = resourceClient(cfg, &fakeResources{}).EKSCluster(context.Background(), scope, "shop-prod")
	wantCode(t, "missing cluster", err, api.CodeUpstreamError)
}

func TestRDSSnapshotsScope(t *testing.T) {
	cfg, scope := resourceScope(t)
	own := &fakeResources{
		clusterSnaps:  []rdstypes.DBClusterSnapshot{{DBClusterIdentifier: sdkaws.String("shop-db")}},
		instanceSnaps: []rdstypes.DBSnapshot{{DBInstanceIdentifier: sdkaws.String("shop-legacy")}},
	}
	if snaps, _, err := resourceClient(cfg, own).RDSClusterSnapshots(context.Background(), scope, "shop-db"); err != nil || len(snaps) != 1 {
		t.Errorf("cluster snapshots = %v, err = %v", snaps, err)
	}
	if snaps, _, err := resourceClient(cfg, own).RDSInstanceSnapshots(context.Background(), scope, "shop-legacy"); err != nil || len(snaps) != 1 {
		t.Errorf("instance snapshots = %v, err = %v", snaps, err)
	}
	foreign := &fakeResources{
		clusterSnaps:  []rdstypes.DBClusterSnapshot{{DBClusterIdentifier: sdkaws.String("other-db")}},
		instanceSnaps: []rdstypes.DBSnapshot{{DBInstanceIdentifier: sdkaws.String("other")}},
	}
	_, _, err := resourceClient(cfg, foreign).RDSClusterSnapshots(context.Background(), scope, "shop-db")
	wantCode(t, "snapshot of another cluster", err, api.CodeInternal)
	_, _, err = resourceClient(cfg, foreign).RDSInstanceSnapshots(context.Background(), scope, "shop-legacy")
	wantCode(t, "snapshot of another instance", err, api.CodeInternal)
	_, _, err = resourceClient(cfg, own).RDSClusterSnapshots(context.Background(), scope, "other-db")
	wantCode(t, "unbound cluster", err, api.CodeInternal)
	_, _, err = resourceClient(cfg, own).RDSInstanceSnapshots(context.Background(), scope, "shop-db-1")
	wantCode(t, "unbound instance", err, api.CodeInternal)
}

func TestCacheUpdateActionsScope(t *testing.T) {
	cfg, scope := resourceScope(t)
	own := &fakeResources{updateActions: []ectypes.UpdateAction{{ReplicationGroupId: sdkaws.String("shop-cache")}}}
	if actions, truncated, err := resourceClient(cfg, own).CacheUpdateActions(context.Background(), scope, "shop-cache"); err != nil || len(actions) != 1 || truncated {
		t.Errorf("actions = %v, truncated = %v, err = %v", actions, truncated, err)
	}
	foreign := &fakeResources{updateActions: []ectypes.UpdateAction{{ReplicationGroupId: sdkaws.String("other")}}}
	_, _, err := resourceClient(cfg, foreign).CacheUpdateActions(context.Background(), scope, "shop-cache")
	wantCode(t, "update of another group", err, api.CodeInternal)
	_, _, err = resourceClient(cfg, own).CacheUpdateActions(context.Background(), scope, "other")
	wantCode(t, "unbound group", err, api.CodeInternal)
	many := &fakeResources{updateActions: slices.Repeat(own.updateActions, maxResourceEvents+1)}
	if actions, truncated, err := resourceClient(cfg, many).CacheUpdateActions(context.Background(), scope, "shop-cache"); err != nil || len(actions) != maxResourceEvents || !truncated {
		t.Errorf("actions = %d, truncated = %v, err = %v", len(actions), truncated, err)
	}
}

func TestRDSMajorEngineVersionSkipsEnginesWithoutLifecycle(t *testing.T) {
	cfg, _ := resourceScope(t)
	fake := &fakeResources{}
	for _, engine := range []string{"docdb", "neptune"} {
		if lifecycles, err := resourceClient(cfg, fake).RDSMajorEngineVersion(context.Background(), engine, "5"); err != nil || lifecycles != nil {
			t.Errorf("%s: lifecycles = %v, err = %v", engine, lifecycles, err)
		}
	}
	if _, err := resourceClient(cfg, fake).RDSMajorEngineVersion(context.Background(), "aurora-postgresql", "16"); err != nil || fake.majorCalls != 1 {
		t.Errorf("aurora-postgresql: calls = %d, err = %v", fake.majorCalls, err)
	}
}
