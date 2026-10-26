package store

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/contember/sonda/internal/issuer"
)

func TestSigningKeys(t *testing.T) {
	forEachDatabase(t, func(t *testing.T, st *Store) {
		ctx := context.Background()
		older := issuer.Key{ID: "b", PrivateKey: []byte{1, 2, 3}, CreatedAt: time.Unix(1_700_000_000, 0)}
		newer := issuer.Key{ID: "a", PrivateKey: []byte{4, 5, 6}, CreatedAt: time.Unix(1_700_000_100, 0)}
		for _, key := range []issuer.Key{newer, older} {
			if err := st.AddSigningKey(ctx, key); err != nil {
				t.Fatal(err)
			}
		}
		keys, err := st.SigningKeys(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if len(keys) != 2 || keys[0].ID != "b" || keys[1].ID != "a" {
			t.Fatalf("keys = %+v, want oldest first", keys)
		}
		if !bytes.Equal(keys[1].PrivateKey, newer.PrivateKey) || !keys[1].CreatedAt.Equal(newer.CreatedAt) {
			t.Errorf("key = %+v, want %+v", keys[1], newer)
		}
	})
}

func TestIssuerKeepsItsKeyInTheStore(t *testing.T) {
	forEachDatabase(t, func(t *testing.T, st *Store) {
		ctx := context.Background()
		for range 2 {
			if _, err := issuer.Open(ctx, "https://sonda.example.com", st); err != nil {
				t.Fatal(err)
			}
		}
		keys, err := st.SigningKeys(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if len(keys) != 1 {
			t.Errorf("two opens stored %d keys, want 1", len(keys))
		}
	})
}
