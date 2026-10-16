// Package httpapi exposes the query use cases over HTTP.
package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strings"

	"github.com/contember/sonda/api"
	"github.com/contember/sonda/internal/apierr"
	"github.com/contember/sonda/internal/authz"
	"github.com/contember/sonda/internal/config"
	"github.com/contember/sonda/internal/query"
)

type Server struct {
	query *query.Service
	authz *authz.Authorizer
	log   *slog.Logger
}

func New(q *query.Service, authorizer *authz.Authorizer, log *slog.Logger) http.Handler {
	s := &Server{query: q, authz: authorizer, log: log}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	mux.Handle("GET /v1/services", s.handle(s.listServices))
	mux.Handle("GET /v1/services/{service}", s.handle(s.describeService))
	mux.Handle("GET /v1/services/{service}/metrics", s.handle(s.metricNames))
	mux.Handle("GET /v1/services/{service}/signals/{signal}", s.handle(s.signal))
	mux.Handle("POST /v1/services/{service}/metrics/query", s.handle(s.queryMetrics))
	mux.Handle("POST /v1/services/{service}/logs/search", s.handle(s.searchLogs))
	mux.Handle("POST /v1/services/{service}/logs/query", s.handle(s.queryLogs))
	mux.Handle("GET /v1/services/{service}/logs/fields", s.handle(s.logFields))
	mux.Handle("GET /v1/results/{id}", s.handle(s.result))
	return mux
}

type identityKey struct{}

func identityFrom(ctx context.Context) *config.Identity {
	return ctx.Value(identityKey{}).(*config.Identity)
}

type handlerFunc func(r *http.Request) (any, error)

// handle authenticates the request, runs the handler and encodes the result or error.
func (s *Server) handle(h handlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		identity, authenticated := s.authz.Authenticate(token)
		if !ok || !authenticated {
			s.writeError(w, apierr.New(api.CodeUnauthenticated, "missing or invalid bearer token"))
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), identity.Limits.QueryTimeout)
		defer cancel()
		r = r.WithContext(context.WithValue(ctx, identityKey{}, identity))

		result, err := h(r)
		if err != nil {
			s.writeError(w, err)
			return
		}
		var body bytes.Buffer
		if err := json.NewEncoder(&body).Encode(result); err != nil {
			s.writeError(w, err)
			return
		}
		if body.Len() > identity.Limits.MaxResponseBytes {
			s.writeError(w, apierr.New(api.CodeLimitExceeded,
				"response has %d bytes, the limit is %d; narrow the time range or lower the limit",
				body.Len(), identity.Limits.MaxResponseBytes))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body.Bytes())
	})
}

func (s *Server) writeError(w http.ResponseWriter, err error) {
	e, ok := apierr.As(err)
	if !ok {
		switch {
		case errors.Is(err, context.DeadlineExceeded):
			e = apierr.New(api.CodeTimeout, "query timed out")
		default:
			s.log.Error("request failed", "error", err)
			e = apierr.New(api.CodeInternal, "internal error")
		}
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusOf(e.Code))
	_ = json.NewEncoder(w).Encode(api.ErrorResponse{Error: api.ErrorBody{Code: e.Code, Message: e.Message}})
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
