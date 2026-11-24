package aws

import (
	"context"
	"errors"
	"maps"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/ecr"
	ecrtypes "github.com/aws/aws-sdk-go-v2/service/ecr/types"
	"golang.org/x/sync/singleflight"
)

const (
	// scanCacheEntries bounds the scan summaries one source keeps; the oldest stored goes first.
	scanCacheEntries = 4096
	// settledScanTTL serves a completed or active scan without asking ECR. A basic scan changes
	// only when it is rerun; an enhanced scan when Inspector rescans, which the TTL bounds.
	settledScanTTL = 10 * time.Minute
	// pendingScanTTL serves any other state, or no scan, only long enough to absorb a burst.
	pendingScanTTL = 30 * time.Second
)

// scanKey names a scan within one source; a source reads one registry, its account's own.
type scanKey struct {
	repository string
	digest     string
}

type scanEntry struct {
	// scan is the summary of the latest scan, nil when the image was never scanned.
	scan    *ecr.DescribeImageScanFindingsOutput
	expires time.Time
	// stored orders entries for eviction, oldest stored first.
	stored uint64
}

// scanCache keeps the scan summaries of listed images, so repeated listings do not exhaust
// ECR's DescribeImageScanFindings rate. Concurrent loads of one key share a single call.
type scanCache struct {
	mu      sync.Mutex
	entries map[scanKey]scanEntry
	stores  uint64
	loads   singleflight.Group
	now     func() time.Time
}

func newScanCache(now func() time.Time) *scanCache {
	return &scanCache{entries: map[scanKey]scanEntry{}, now: now}
}

// get returns the cached summary of key or loads it. listed is the image as DescribeImages
// returned it, or nil; a scan status or completion time it states that differs from the cached
// one means a newer scan, and the summary is loaded again. Errors are not cached.
func (c *scanCache) get(ctx context.Context, key scanKey, listed *ecrtypes.ImageDetail, load func(context.Context) (*ecr.DescribeImageScanFindingsOutput, error)) (*ecr.DescribeImageScanFindingsOutput, error) {
	if scan, ok := c.lookup(key, listed); ok {
		return scan, nil
	}
	loads := c.loads.DoChan(key.repository+"@"+key.digest, func() (any, error) {
		// A load that finished between the lookup above and this call has stored the summary.
		if scan, ok := c.lookup(key, listed); ok {
			return scan, nil
		}
		scan, err := load(ctx)
		if err != nil {
			return nil, err
		}
		return c.store(key, scan), nil
	})
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case res := <-loads:
		if res.Err != nil {
			// The shared load ran under the context of another request, which ended first.
			if ctx.Err() == nil && (errors.Is(res.Err, context.Canceled) || errors.Is(res.Err, context.DeadlineExceeded)) {
				scan, err := load(ctx)
				if err != nil {
					return nil, err
				}
				return c.store(key, scan), nil
			}
			return nil, res.Err
		}
		scan, _ := res.Val.(*ecr.DescribeImageScanFindingsOutput)
		return scanSummary(scan), nil
	}
}

// lookup returns a copy of the cached summary of key while it is fresh and agrees with listed.
func (c *scanCache) lookup(key scanKey, listed *ecrtypes.ImageDetail) (*ecr.DescribeImageScanFindingsOutput, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	entry, ok := c.entries[key]
	if !ok || !c.now().Before(entry.expires) || !agrees(entry.scan, listed) {
		return nil, false
	}
	return scanSummary(entry.scan), true
}

// store keeps the summary of scan under key, drops the oldest stored entry over the bound, and
// returns a copy of the summary.
func (c *scanCache) store(key scanKey, scan *ecr.DescribeImageScanFindingsOutput) *ecr.DescribeImageScanFindingsOutput {
	entry := scanEntry{scan: scanSummary(scan), expires: c.now().Add(scanTTL(scan))}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.stores++
	entry.stored = c.stores
	c.entries[key] = entry
	if len(c.entries) > scanCacheEntries {
		// A linear pass, only when full: a listing stores at most a few hundred summaries.
		var oldest scanKey
		first := true
		for k, e := range c.entries {
			if first || e.stored < c.entries[oldest].stored {
				oldest, first = k, false
			}
		}
		delete(c.entries, oldest)
	}
	return scanSummary(entry.scan)
}

// scanTTL is settledScanTTL for a completed or active scan, pendingScanTTL for any other state
// (in progress, pending, failed, unsupported) and for an image never scanned.
func scanTTL(scan *ecr.DescribeImageScanFindingsOutput) time.Duration {
	if scan == nil || scan.ImageScanStatus == nil {
		return pendingScanTTL
	}
	switch scan.ImageScanStatus.Status {
	case ecrtypes.ScanStatusComplete, ecrtypes.ScanStatusActive:
		return settledScanTTL
	}
	return pendingScanTTL
}

// agrees reports whether the cached scan matches what DescribeImages stated about the image.
// Under registry-level scanning DescribeImages states neither, and only the TTL applies.
func agrees(scan *ecr.DescribeImageScanFindingsOutput, listed *ecrtypes.ImageDetail) bool {
	if listed == nil {
		return true
	}
	if status := listed.ImageScanStatus; status != nil {
		if scan == nil || scan.ImageScanStatus == nil || scan.ImageScanStatus.Status != status.Status {
			return false
		}
	}
	if summary := listed.ImageScanFindingsSummary; summary != nil && summary.ImageScanCompletedAt != nil {
		if scan == nil || scan.ImageScanFindings == nil || scan.ImageScanFindings.ImageScanCompletedAt == nil ||
			!scan.ImageScanFindings.ImageScanCompletedAt.Equal(*summary.ImageScanCompletedAt) {
			return false
		}
	}
	return true
}

// scanSummary copies the status and counts of scan without its findings, so a cached summary
// shares no memory with its callers.
func scanSummary(scan *ecr.DescribeImageScanFindingsOutput) *ecr.DescribeImageScanFindingsOutput {
	if scan == nil {
		return nil
	}
	summary := &ecr.DescribeImageScanFindingsOutput{
		RegistryId:     copyPtr(scan.RegistryId),
		RepositoryName: copyPtr(scan.RepositoryName),
	}
	if scan.ImageId != nil {
		summary.ImageId = &ecrtypes.ImageIdentifier{ImageDigest: copyPtr(scan.ImageId.ImageDigest), ImageTag: copyPtr(scan.ImageId.ImageTag)}
	}
	if scan.ImageScanStatus != nil {
		summary.ImageScanStatus = &ecrtypes.ImageScanStatus{Status: scan.ImageScanStatus.Status, Description: copyPtr(scan.ImageScanStatus.Description)}
	}
	if findings := scan.ImageScanFindings; findings != nil {
		summary.ImageScanFindings = &ecrtypes.ImageScanFindings{
			FindingSeverityCounts:        maps.Clone(findings.FindingSeverityCounts),
			ImageScanCompletedAt:         copyPtr(findings.ImageScanCompletedAt),
			VulnerabilitySourceUpdatedAt: copyPtr(findings.VulnerabilitySourceUpdatedAt),
		}
	}
	return summary
}

func copyPtr[T any](p *T) *T {
	if p == nil {
		return nil
	}
	v := *p
	return &v
}
