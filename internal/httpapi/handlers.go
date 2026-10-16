package httpapi

import (
	"net/http"

	"github.com/contember/sonda/api"
)

func (s *Server) listServices(r *http.Request) (any, error) {
	return s.query.ListServices(identityFrom(r.Context())), nil
}

func (s *Server) describeService(r *http.Request) (any, error) {
	return s.query.DescribeService(identityFrom(r.Context()), r.PathValue("service"))
}

func (s *Server) metricNames(r *http.Request) (any, error) {
	w, err := windowFromQuery(r)
	if err != nil {
		return nil, err
	}
	return s.query.MetricNames(r.Context(), identityFrom(r.Context()), r.PathValue("service"), w, r.URL.Query().Get("filter"))
}

func (s *Server) signal(r *http.Request) (any, error) {
	w, err := windowFromQuery(r)
	if err != nil {
		return nil, err
	}
	points, err := boolParam(r, "points", true)
	if err != nil {
		return nil, err
	}
	return s.query.Signal(r.Context(), identityFrom(r.Context()), r.PathValue("service"), r.PathValue("signal"), w, r.URL.Query().Get("step"), points)
}

func (s *Server) queryMetrics(r *http.Request) (any, error) {
	var req api.MetricQueryRequest
	if err := decodeBody(r, &req); err != nil {
		return nil, err
	}
	points, err := boolParam(r, "points", true)
	if err != nil {
		return nil, err
	}
	return s.query.QueryMetrics(r.Context(), identityFrom(r.Context()), r.PathValue("service"), req, points)
}
