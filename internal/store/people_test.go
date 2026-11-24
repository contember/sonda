package store

import (
	"context"
	"crypto/sha256"
	"errors"
	"testing"
	"time"

	"github.com/contember/sonda/internal/identities"
)

func TestPeople(t *testing.T) {
	forEachDatabase(t, func(t *testing.T, st *Store) {
		ctx := context.Background()
		created := time.UnixMilli(1_700_000_000_000)
		for _, name := range []string{"alice", "bob"} {
			_, hash := identities.NewToken()
			if err := st.Create(ctx, identities.Identity{Name: name, TokenSHA256: hash, CreatedAt: created}); err != nil {
				t.Fatal(err)
			}
		}
		alice := Person{Identity: "alice", Issuer: "https://iam.example.com", Subject: "p1", Admin: true, CreatedAt: created}
		if err := st.LinkPerson(ctx, alice); err != nil {
			t.Fatal(err)
		}
		if got, err := st.PersonBySubject(ctx, alice.Issuer, "p1"); err != nil || got != alice {
			t.Errorf("by subject: %+v, %v", got, err)
		}
		if _, err := st.PersonBySubject(ctx, "https://other.example.com", "p1"); !errors.Is(err, ErrPersonNotFound) {
			t.Errorf("same subject at another issuer: %v", err)
		}
		if err := st.LinkPerson(ctx, Person{Identity: "bob", Issuer: alice.Issuer, Subject: "p1", CreatedAt: created}); !errors.Is(err, ErrSubjectTaken) {
			t.Errorf("subject of another identity: %v", err)
		}
		if err := st.LinkPerson(ctx, Person{Identity: "carol", Issuer: alice.Issuer, Subject: "p3", CreatedAt: created}); !errors.Is(err, ErrIdentityNotFound) {
			t.Errorf("unknown identity: %v", err)
		}
		// Linking again replaces the identity's link.
		alice.Subject, alice.Admin = "p2", false
		if err := st.LinkPerson(ctx, alice); err != nil {
			t.Fatal(err)
		}
		if got, err := st.PersonByIdentity(ctx, "alice"); err != nil || got != alice {
			t.Errorf("relinked: %+v, %v", got, err)
		}
		if people, err := st.People(ctx); err != nil || len(people) != 1 {
			t.Errorf("people: %+v, %v", people, err)
		}
		if err := st.Delete(ctx, "alice"); err != nil {
			t.Fatal(err)
		}
		if _, err := st.PersonBySubject(ctx, alice.Issuer, "p2"); !errors.Is(err, ErrPersonNotFound) {
			t.Errorf("link outlived its identity: %v", err)
		}
	})
}

func TestAdminSessions(t *testing.T) {
	forEachDatabase(t, func(t *testing.T, st *Store) {
		ctx := context.Background()
		now := time.Unix(1_700_000_000, 0)
		st.now = func() time.Time { return now }
		id := sha256.Sum256([]byte("cookie"))
		session := AdminSession{Kind: SessionPersonLink, Issuer: "https://iam.example.com", Subject: "p1", Label: "alice", Credential: []byte{}, ExpiresAt: now.Add(time.Hour)}
		if err := st.CreateAdminSession(ctx, id, session); err != nil {
			t.Fatal(err)
		}
		got, err := st.AdminSession(ctx, id)
		if err != nil || got.Kind != session.Kind || got.Subject != "p1" || !got.ExpiresAt.Equal(session.ExpiresAt) {
			t.Errorf("session %+v, %v", got, err)
		}
		now = now.Add(time.Hour)
		if _, err := st.AdminSession(ctx, id); !errors.Is(err, ErrSessionNotFound) {
			t.Errorf("expired session: %v", err)
		}
		other := sha256.Sum256([]byte("other"))
		if err := st.CreateAdminSession(ctx, other, AdminSession{Kind: SessionBreakGlass, Credential: []byte{1, 2}, ExpiresAt: now.Add(time.Hour)}); err != nil {
			t.Fatal(err)
		}
		if err := st.DeleteAdminSession(ctx, other); err != nil {
			t.Fatal(err)
		}
		if _, err := st.AdminSession(ctx, other); !errors.Is(err, ErrSessionNotFound) {
			t.Errorf("deleted session: %v", err)
		}
	})
}
