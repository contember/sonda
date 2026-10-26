// Package httpapi exposes the query use cases over HTTP.
package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/contember/sonda/api"
	"github.com/contember/sonda/internal/apierr"
	"github.com/contember/sonda/internal/audit"
	"github.com/contember/sonda/internal/authz"
	"github.com/contember/sonda/internal/query"
	"github.com/contember/sonda/internal/store"
)

type Server struct {
	query    *query.Service
	authz    *authz.Authorizer
	store    *store.Store
	limiters *limiters
	log      *slog.Logger
}

func New(q *query.Service, authorizer *authz.Authorizer, st *store.Store, log *slog.Logger) http.Handler {
	s := &Server{query: q, authz: authorizer, store: st, limiters: newLimiters(), log: log}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	mux.Handle("GET /v1/services", s.handle(s.listServices))
	mux.Handle("GET /v1/services/{service}", s.handle(s.describeService))
	mux.Handle("GET /v1/services/{service}/overview", s.handle(s.overview))
	mux.Handle("GET /v1/services/{service}/errors", s.handle(s.listErrors))
	mux.Handle("GET /v1/services/{service}/errors/{id}", s.handle(s.getError))
	mux.Handle("GET /v1/services/{service}/releases", s.handle(s.releases))
	mux.Handle("GET /v1/services/{service}/metrics", s.handle(s.metricNames))
	mux.Handle("GET /v1/services/{service}/signals/{signal}", s.handle(s.signal))
	mux.Handle("POST /v1/services/{service}/metrics/query", s.handle(s.queryMetrics))
	mux.Handle("POST /v1/services/{service}/logs/search", s.handle(s.searchLogs))
	mux.Handle("POST /v1/services/{service}/logs/query", s.handle(s.queryLogs))
	mux.Handle("GET /v1/services/{service}/logs/fields", s.handle(s.logFields))
	mux.Handle("POST /v1/services/{service}/traces/search", s.handle(s.searchTraces))
	mux.Handle("POST /v1/services/{service}/traces/query", s.handle(s.queryTraces))
	mux.Handle("GET /v1/services/{service}/traces/{id}", s.handle(s.getTrace))
	mux.Handle("GET /v1/services/{service}/workloads", s.handle(s.workloads))
	mux.Handle("GET /v1/results/{id}", s.handle(s.result))
	return mux
}

type identityKey struct{}

func identityFrom(ctx context.Context) *authz.Identity {
	return ctx.Value(identityKey{}).(*authz.Identity)
}

type handlerFunc func(r *http.Request) (any, error)

// handle runs the handler, writes the result or error and records one audit entry,
// also for rejected requests.
func (s *Server) handle(h handlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		ctx, record := audit.WithRecord(r.Context())
		identity, body, err := s.run(r.WithContext(ctx), h)
		status, code := http.StatusOK, api.ErrorCode("")
		if err != nil {
			e := s.clientError(err)
			status, code = statusOf(e.Code), e.Code
			body, _ = json.Marshal(api.ErrorResponse{Error: api.ErrorBody{Code: e.Code, Message: e.Message}})
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write(body)
		s.writeAudit(r, identity, record, status, code, time.Since(start), len(body))
	})
}

// run authenticates, applies the identity's limits and encodes the handler's result.
func (s *Server) run(r *http.Request, h handlerFunc) (*authz.Identity, []byte, error) {
	token, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok {
		token = ""
	}
	identity, err := s.authz.Authenticate(r.Context(), token)
	if err != nil {
		return nil, nil, err
	}
	release, err := s.limiters.acquire(identity)
	if err != nil {
		return identity, nil, err
	}
	defer release()

	ctx, cancel := context.WithTimeout(r.Context(), identity.Limits.QueryTimeout)
	defer cancel()
	result, err := h(r.WithContext(context.WithValue(ctx, identityKey{}, identity)))
	if err != nil {
		return identity, nil, err
	}
	body, err := json.Marshal(result)
	if err != nil {
		return identity, nil, err
	}
	if len(body) > identity.Limits.MaxResponseBytes {
		return identity, nil, apierr.New(api.CodeLimitExceeded,
			"response has %d bytes, the limit is %d; narrow the time range or lower the limit",
			len(body), identity.Limits.MaxResponseBytes)
	}
	return identity, body, nil
}

// clientError converts any error into one that is safe to return. Unexpected errors are
// logged and reported without details.
func (s *Server) clientError(err error) *apierr.Error {
	if e, ok := apierr.As(err); ok {
		return e
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return apierr.New(api.CodeTimeout, "query timed out")
	}
	s.log.Error("request failed", "error", err)
	return apierr.New(api.CodeInternal, "internal error")
}

func (s *Server) writeAudit(r *http.Request, identity *authz.Identity, record *audit.Record, status int, code api.ErrorCode, duration time.Duration, size int) {
	service, environment, queries := record.Snapshot()
	entry := store.AuditEntry{
		Time:          time.Now(),
		Method:        r.Method,
		Path:          r.URL.Path,
		Service:       service,
		Environment:   environment,
		Queries:       strings.Join(queries, "\n"),
		Status:        status,
		ErrorCode:     string(code),
		Duration:      duration,
		ResponseBytes: size,
	}
	if identity != nil {
		entry.Identity = identity.Name
	}
	if err := s.store.WriteAudit(context.WithoutCancel(r.Context()), entry); err != nil {
		s.log.Error("audit write failed", "error", err)
	}
}

func statusOf(code api.ErrorCode) int {
	switch code {
	case api.CodeUnauthenticated:
		return http.StatusUnauthorized
	case api.CodeNotFound:
		return http.StatusNotFound
	case api.CodeInvalidRequest, api.CodeInvalidQuery:
		return http.StatusBadRequest
	case api.CodeLimitExceeded:
		return http.StatusUnprocessableEntity
	case api.CodeRateLimited:
		return http.StatusTooManyRequests
	case api.CodeUpstreamError:
		return http.StatusBadGateway
	case api.CodeTimeout:
		return http.StatusGatewayTimeout
	default:
		return http.StatusInternalServerError
	}
}
