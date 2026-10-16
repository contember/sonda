// Package audit collects what a request did, so the HTTP layer can persist one record per
// request, including the final upstream queries.
package audit

import (
	"context"
	"sync"
)

type Record struct {
	mu          sync.Mutex
	service     string
	environment string
	queries     []string
}

type key struct{}

func WithRecord(ctx context.Context) (context.Context, *Record) {
	r := &Record{}
	return context.WithValue(ctx, key{}, r), r
}

func FromContext(ctx context.Context) *Record {
	r, _ := ctx.Value(key{}).(*Record)
	return r
}

// AddQuery records an upstream query. Overview requests run queries concurrently.
func (r *Record) AddQuery(service, environment, query string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.service, r.environment = service, environment
	r.queries = append(r.queries, query)
}

func (r *Record) Snapshot() (service, environment string, queries []string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.service, r.environment, append([]string(nil), r.queries...)
}
