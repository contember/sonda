package aws

import (
	"context"
	"fmt"
	"slices"
	"sync/atomic"
	"testing"
	"time"

	sdkaws "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ecr"
	ecrtypes "github.com/aws/aws-sdk-go-v2/service/ecr/types"
)

// cachingClient returns a client over fake whose scan cache reads the time from *now.
func cachingClient(t *testing.T, fake *fakeECR) (*Client, *time.Time, func(listed *ecrtypes.ImageDetail) *ecrtypes.ImageScanStatus) {
	t.Helper()
	cfg, scope := imageScope(t)
	if fake.findings == nil {
		fake.findings = [][]ecrtypes.ImageScanFinding{{}}
	}
	c := ecrClient(cfg, fake)
	now := time.Date(2026, 11, 24, 12, 0, 0, 0, time.UTC)
	c.scans.now = func() time.Time { return now }
	scan := func(listed *ecrtypes.ImageDetail) *ecrtypes.ImageScanStatus {
		t.Helper()
		out, err := c.Scan(context.Background(), scope, "shop", testDigest, listed)
		if err != nil {
			t.Fatal(err)
		}
		if out == nil {
			return nil
		}
		return out.ImageScanStatus
	}
	return c, &now, scan
}

func TestScanCachedPerDigest(t *testing.T) {
	fake := &fakeECR{}
	_, now, scan := cachingClient(t, fake)
	if status := scan(nil); status == nil || status.Status != ecrtypes.ScanStatusComplete {
		t.Fatalf("status = %+v", status)
	}
	*now = now.Add(settledScanTTL - time.Second)
	if status := scan(nil); status == nil || status.Status != ecrtypes.ScanStatusComplete {
		t.Fatalf("cached status = %+v", status)
	}
	if len(fake.scanned) != 1 {
		t.Fatalf("DescribeImageScanFindings calls = %v, want one for a completed scan read twice", fake.scanned)
	}
	*now = now.Add(time.Second)
	scan(nil)
	if len(fake.scanned) != 2 {
		t.Errorf("DescribeImageScanFindings calls = %v, want a second one once the TTL passed", fake.scanned)
	}
}

func TestScanCacheKeepsFinalStates(t *testing.T) {
	for _, status := range []ecrtypes.ScanStatus{ecrtypes.ScanStatusActive, ecrtypes.ScanStatusUnsupportedImage, ecrtypes.ScanStatusScanEligibilityExpired} {
		fake := &fakeECR{status: status}
		_, now, scan := cachingClient(t, fake)
		scan(nil)
		*now = now.Add(settledScanTTL - time.Second)
		scan(nil)
		if len(fake.scanned) != 1 {
			t.Errorf("status %q: DescribeImageScanFindings calls = %d, want 1", status, len(fake.scanned))
		}
	}
}

func TestScanCacheBriefForUnsettledScans(t *testing.T) {
	for _, fake := range []*fakeECR{{status: ecrtypes.ScanStatusInProgress}, {status: ecrtypes.ScanStatusPending}, {status: ecrtypes.ScanStatusFailed}, {noScan: true}} {
		_, now, scan := cachingClient(t, fake)
		scan(nil)
		*now = now.Add(pendingScanTTL - time.Second)
		scan(nil)
		*now = now.Add(time.Second)
		scan(nil)
		if len(fake.scanned) != 2 {
			t.Errorf("status %q, no scan %v: DescribeImageScanFindings calls = %d, want 2", fake.status, fake.noScan, len(fake.scanned))
		}
	}
}

func TestScanCacheRefreshesWhenListedScanChanges(t *testing.T) {
	completed := time.Date(2026, 11, 24, 11, 0, 0, 0, time.UTC)
	fake := &fakeECR{completedAt: &completed}
	_, _, scan := cachingClient(t, fake)
	listed := func(status ecrtypes.ScanStatus, completedAt time.Time) *ecrtypes.ImageDetail {
		return &ecrtypes.ImageDetail{
			ImageScanStatus:          &ecrtypes.ImageScanStatus{Status: status},
			ImageScanFindingsSummary: &ecrtypes.ImageScanFindingsSummary{ImageScanCompletedAt: sdkaws.Time(completedAt)},
		}
	}

	scan(listed(ecrtypes.ScanStatusComplete, completed))
	scan(listed(ecrtypes.ScanStatusComplete, completed))
	scan(&ecrtypes.ImageDetail{})
	if len(fake.scanned) != 1 {
		t.Fatalf("DescribeImageScanFindings calls = %d, want 1 while DescribeImages agrees or states nothing", len(fake.scanned))
	}

	// A rescan: DescribeImages states a later completion time.
	rescanned := completed.Add(time.Hour)
	fake.completedAt = &rescanned
	scan(listed(ecrtypes.ScanStatusComplete, rescanned))
	if len(fake.scanned) != 2 {
		t.Fatalf("DescribeImageScanFindings calls = %d, want a refresh after a new completion time", len(fake.scanned))
	}

	// A rescan in progress: DescribeImages states another status.
	fake.status = ecrtypes.ScanStatusInProgress
	if status := scan(listed(ecrtypes.ScanStatusInProgress, rescanned)); status == nil || status.Status != ecrtypes.ScanStatusInProgress {
		t.Errorf("status = %+v, want IN_PROGRESS", status)
	}
	if len(fake.scanned) != 3 {
		t.Errorf("DescribeImageScanFindings calls = %d, want a refresh after a new status", len(fake.scanned))
	}
}

func TestScanCacheKeepsNoErrors(t *testing.T) {
	cfg, scope := imageScope(t)
	fake := &fakeECR{throttled: 1, findings: [][]ecrtypes.ImageScanFinding{{}}}
	c := ecrClient(cfg, fake)
	if _, err := c.Scan(context.Background(), scope, "shop", testDigest, nil); err == nil {
		t.Fatal("throttled call: want an error")
	}
	out, err := c.Scan(context.Background(), scope, "shop", testDigest, nil)
	if err != nil || out == nil || len(fake.scanned) != 2 {
		t.Errorf("after a throttled call: scan = %+v, err = %v, calls = %d", out, err, len(fake.scanned))
	}
}

func TestScanCacheIsBounded(t *testing.T) {
	cfg, scope := imageScope(t)
	fake := &fakeECR{findings: [][]ecrtypes.ImageScanFinding{{}}}
	c := ecrClient(cfg, fake)
	digest := func(i int) string { return fmt.Sprintf("sha256:%064x", i) }
	read := func(i int) {
		t.Helper()
		if _, err := c.Scan(context.Background(), scope, "shop", digest(i), nil); err != nil {
			t.Fatal(err)
		}
	}
	for i := range scanCacheEntries + 1 {
		read(i)
	}
	if got := len(c.scans.entries); got != scanCacheEntries {
		t.Fatalf("entries = %d, want %d", got, scanCacheEntries)
	}
	fake.scanned = nil
	read(scanCacheEntries)
	read(1)
	if len(fake.scanned) != 0 {
		t.Errorf("DescribeImageScanFindings calls = %v, want none for the newest entries", fake.scanned)
	}
	read(0)
	if !slices.Equal(fake.scanned, []string{digest(0)}) {
		t.Errorf("DescribeImageScanFindings calls = %v, want one for the oldest, evicted entry", fake.scanned)
	}
}

func TestScanCacheReturnsCopies(t *testing.T) {
	cfg, scope := imageScope(t)
	fake := &fakeECR{findings: [][]ecrtypes.ImageScanFinding{{{Name: sdkaws.String("CVE-1")}}}}
	c := ecrClient(cfg, fake)
	first, err := c.Scan(context.Background(), scope, "shop", testDigest, nil)
	if err != nil {
		t.Fatal(err)
	}
	if first.ImageScanFindings.Findings != nil {
		t.Errorf("summary carries findings: %+v", first.ImageScanFindings.Findings)
	}
	first.ImageScanStatus.Status = ecrtypes.ScanStatusFailed
	second, err := c.Scan(context.Background(), scope, "shop", testDigest, nil)
	if err != nil || second.ImageScanStatus.Status != ecrtypes.ScanStatusComplete || len(fake.scanned) != 1 {
		t.Errorf("second read: scan = %+v, err = %v, calls = %d", second, err, len(fake.scanned))
	}
}

func completeScan() *ecr.DescribeImageScanFindingsOutput {
	return &ecr.DescribeImageScanFindingsOutput{ImageScanStatus: &ecrtypes.ImageScanStatus{Status: ecrtypes.ScanStatusComplete}}
}

// joinDelay gives a second reader time to join a load in flight. With shared loads the tests
// pass however the reader is scheduled; the delay makes a regression to unshared loads show.
const joinDelay = 20 * time.Millisecond

func TestScanCacheSharesConcurrentLoads(t *testing.T) {
	c := newScanCache(time.Now)
	key := scanKey{repository: "shop", digest: testDigest}
	started, release := make(chan struct{}), make(chan struct{})
	var calls atomic.Int32
	load := func(context.Context) (*ecr.DescribeImageScanFindingsOutput, error) {
		if calls.Add(1) == 1 {
			close(started)
			<-release
		}
		return completeScan(), nil
	}
	errs := make(chan error, 2)
	read := func() {
		_, err := c.get(context.Background(), key, nil, load)
		errs <- err
	}
	go read()
	<-started
	go read()
	time.Sleep(joinDelay)
	close(release)
	for range 2 {
		if err := <-errs; err != nil {
			t.Fatal(err)
		}
	}
	if n := calls.Load(); n != 1 {
		t.Errorf("loads = %d, want 1 for two concurrent reads", n)
	}
}

func TestScanCacheWaiterSurvivesCancelledLoad(t *testing.T) {
	c := newScanCache(time.Now)
	key := scanKey{repository: "shop", digest: testDigest}
	started := make(chan struct{})
	var calls atomic.Int32
	load := func(ctx context.Context) (*ecr.DescribeImageScanFindingsOutput, error) {
		if calls.Add(1) == 1 {
			close(started)
			<-ctx.Done()
			return nil, ctx.Err()
		}
		return completeScan(), nil
	}
	leaderCtx, cancel := context.WithCancel(context.Background())
	leader := make(chan error, 1)
	go func() {
		_, err := c.get(leaderCtx, key, nil, load)
		leader <- err
	}()
	<-started
	type result struct {
		scan *ecr.DescribeImageScanFindingsOutput
		err  error
	}
	waiter := make(chan result, 1)
	go func() {
		scan, err := c.get(context.Background(), key, nil, load)
		waiter <- result{scan, err}
	}()
	time.Sleep(joinDelay)
	cancel()
	if err := <-leader; err == nil {
		t.Error("cancelled leader: want an error")
	}
	got := <-waiter
	if got.err != nil || got.scan == nil || got.scan.ImageScanStatus.Status != ecrtypes.ScanStatusComplete {
		t.Errorf("waiter: scan = %+v, err = %v, want the scan of its own load", got.scan, got.err)
	}
	if n := calls.Load(); n != 2 {
		t.Errorf("loads = %d, want the cancelled one and one retry", n)
	}
}
