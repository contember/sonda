package store

import (
	"context"
	"crypto/sha256"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/contember/sonda/api"
	"github.com/contember/sonda/internal/identities"
)

func TestIdentityLifecycle(t *testing.T) {
	forEachDatabase(t, testIdentityLifecycle)
}

func testIdentityLifecycle(t *testing.T, st *Store) {
	ctx := context.Background()
	maxRange := 48 * time.Hour
	lines := 100
	created := identities.Identity{
		Name:        "agent",
		TokenSHA256: sha256.Sum256([]byte("one")),
		Grants: []identities.Grant{
			{Project: "api", Environment: "production", Capability: api.CapabilityLogs},
			{Project: "api", Environment: "production", Capability: api.CapabilityErrors},
		},
		Limits:    identities.LimitOverrides{MaxRange: &maxRange, MaxLogLines: &lines},
		CreatedAt: time.UnixMilli(1_700_000_000_000),
	}
	if err := st.Create(ctx, created); err != nil {
		t.Fatal(err)
	}

	found, err := st.FindByTokenHash(ctx, sha256.Sum256([]byte("one")))
	if err != nil {
		t.Fatal(err)
	}
	// Grants come back sorted by service, environment and capability.
	created.Grants[0], created.Grants[1] = created.Grants[1], created.Grants[0]
	if !reflect.DeepEqual(found, created) {
		t.Errorf("found %+v\nwant  %+v", found, created)
	}

	duplicateName := created
	duplicateName.TokenSHA256 = sha256.Sum256([]byte("two"))
	if err := st.Create(ctx, duplicateName); !errors.Is(err, identities.ErrExists) {
		t.Errorf("duplicate name: %v", err)
	}
	duplicateToken := created
	duplicateToken.Name = "other"
	if err := st.Create(ctx, duplicateToken); !errors.Is(err, identities.ErrExists) {
		t.Errorf("duplicate token: %v", err)
	}

	newGrants := []identities.Grant{{Project: "billing", Environment: "staging", Capability: api.CapabilityMetrics}}
	if err := st.Update(ctx, "agent", newGrants, identities.LimitOverrides{}); err != nil {
		t.Fatal(err)
	}
	updated, err := st.Get(ctx, "agent")
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(updated.Grants, newGrants) || updated.Limits != (identities.LimitOverrides{}) {
		t.Errorf("after update: grants %+v, limits %+v", updated.Grants, updated.Limits)
	}

	if err := st.SetTokenHash(ctx, "agent", sha256.Sum256([]byte("two"))); err != nil {
		t.Fatal(err)
	}
	if _, err := st.FindByTokenHash(ctx, sha256.Sum256([]byte("one"))); !errors.Is(err, identities.ErrNotFound) {
		t.Errorf("old token still found: %v", err)
	}

	if err := st.Delete(ctx, "agent"); err != nil {
		t.Fatal(err)
	}
	if err := st.Delete(ctx, "agent"); !errors.Is(err, identities.ErrNotFound) {
		t.Errorf("second delete: %v", err)
	}
	// Grants of a deleted identity must not reappear for a new identity of the same name.
	recreated := identities.Identity{Name: "agent", TokenSHA256: sha256.Sum256([]byte("three")), CreatedAt: time.Now()}
	if err := st.Create(ctx, recreated); err != nil {
		t.Fatal(err)
	}
	if got, _ := st.Get(ctx, "agent"); len(got.Grants) != 0 {
		t.Errorf("grants survived delete: %+v", got.Grants)
	}
	for _, err := range []error{
		st.Update(ctx, "nope", nil, identities.LimitOverrides{}),
		st.SetTokenHash(ctx, "nope", sha256.Sum256([]byte("four"))),
	} {
		if !errors.Is(err, identities.ErrNotFound) {
			t.Errorf("unknown identity: %v", err)
		}
	}
}
