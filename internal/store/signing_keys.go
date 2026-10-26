package store

import (
	"context"
	"time"

	"github.com/contember/sonda/internal/issuer"
)

var _ issuer.KeyStore = (*Store)(nil)

func (s *Store) SigningKeys(ctx context.Context) ([]issuer.Key, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, private_key, created_at FROM signing_keys ORDER BY created_at, id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var keys []issuer.Key
	for rows.Next() {
		var key issuer.Key
		var createdAt int64
		if err := rows.Scan(&key.ID, &key.PrivateKey, &createdAt); err != nil {
			return nil, err
		}
		key.CreatedAt = time.Unix(createdAt, 0)
		keys = append(keys, key)
	}
	return keys, rows.Err()
}

func (s *Store) AddSigningKey(ctx context.Context, key issuer.Key) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO signing_keys (id, private_key, created_at) VALUES ($1, $2, $3)`,
		key.ID, key.PrivateKey, key.CreatedAt.Unix())
	return err
}
