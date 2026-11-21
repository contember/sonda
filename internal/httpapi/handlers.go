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

func (s *Server) searchLogs(r *http.Request) (any, error) {
	var req api.LogSearchRequest
	if err := decodeBody(r, &req); err != nil {
		return nil, err
	}
	return s.query.SearchLogs(r.Context(), identityFrom(r.Context()), r.PathValue("service"), req)
}

func (s *Server) queryLogs(r *http.Request) (any, error) {
	var req api.LogQueryRequest
	if err := decodeBody(r, &req); err != nil {
		return nil, err
	}
	return s.query.QueryLogs(r.Context(), identityFrom(r.Context()), r.PathValue("service"), req)
}

func (s *Server) logFields(r *http.Request) (any, error) {
	w, err := windowFromQuery(r)
	if err != nil {
		return nil, err
	}
	return s.query.LogFields(r.Context(), identityFrom(r.Context()), r.PathValue("service"), w)
}

func (s *Server) searchTraces(r *http.Request) (any, error) {
	var req api.TraceSearchRequest
	if err := decodeBody(r, &req); err != nil {
		return nil, err
	}
	return s.query.SearchTraces(r.Context(), identityFrom(r.Context()), r.PathValue("service"), req)
}

func (s *Server) queryTraces(r *http.Request) (any, error) {
	var req api.TraceQueryRequest
	if err := decodeBody(r, &req); err != nil {
		return nil, err
	}
	return s.query.QueryTraces(r.Context(), identityFrom(r.Context()), r.PathValue("service"), req)
}

func (s *Server) getTrace(r *http.Request) (any, error) {
	w, err := windowFromQuery(r)
	if err != nil {
		return nil, err
	}
	return s.query.GetTrace(r.Context(), identityFrom(r.Context()), r.PathValue("service"), r.PathValue("id"), w)
}

func (s *Server) workloads(r *http.Request) (any, error) {
	w, err := windowFromQuery(r)
	if err != nil {
		return nil, err
	}
	return s.query.Workloads(r.Context(), identityFrom(r.Context()), r.PathValue("service"), w)
}

// objects takes only env: it reads the current configuration.
func (s *Server) objects(r *http.Request) (any, error) {
	return s.query.Objects(r.Context(), identityFrom(r.Context()), r.PathValue("service"), r.URL.Query().Get("env"))
}

// images and image take no range: they read the registry's current state.
func (s *Server) images(r *http.Request) (any, error) {
	req, err := imagesRequest(r)
	if err != nil {
		return nil, err
	}
	req.Digests = r.URL.Query()["digest"]
	return s.query.Images(r.Context(), identityFrom(r.Context()), r.PathValue("service"), req)
}

func (s *Server) image(r *http.Request) (any, error) {
	req, err := imagesRequest(r)
	if err != nil {
		return nil, err
	}
	return s.query.Image(r.Context(), identityFrom(r.Context()), r.PathValue("service"), r.PathValue("digest"), req)
}

func imagesRequest(r *http.Request) (api.ImagesRequest, error) {
	limit, err := intParam(r, "limit", 0)
	if err != nil {
		return api.ImagesRequest{}, err
	}
	params := r.URL.Query()
	return api.ImagesRequest{Environment: params.Get("env"), Repository: params.Get("repository"), Limit: limit}, nil
}

// resources reads the current configuration state; the range selects only the events.
func (s *Server) resources(r *http.Request) (any, error) {
	w, err := windowFromQuery(r)
	if err != nil {
		return nil, err
	}
	return s.query.Resources(r.Context(), identityFrom(r.Context()), r.PathValue("service"), w)
}

// alerts takes only env: alerts are current state.
func (s *Server) alerts(r *http.Request) (any, error) {
	return s.query.Alerts(r.Context(), identityFrom(r.Context()), r.PathValue("service"), r.URL.Query().Get("env"))
}

func (s *Server) result(r *http.Request) (any, error) {
	var group *int
	if r.URL.Query().Has("group") {
		g, err := intParam(r, "group", 0)
		if err != nil {
			return nil, err
		}
		group = &g
	}
	offset, err := intParam(r, "offset", 0)
	if err != nil {
		return nil, err
	}
	limit, err := intParam(r, "limit", 0)
	if err != nil {
		return nil, err
	}
	return s.query.Result(r.Context(), identityFrom(r.Context()), r.PathValue("id"), group, offset, limit)
}

func (s *Server) overview(r *http.Request) (any, error) {
	w, err := windowFromQuery(r)
	if err != nil {
		return nil, err
	}
	return s.query.Overview(r.Context(), identityFrom(r.Context()), r.PathValue("service"), w)
}

func (s *Server) listErrors(r *http.Request) (any, error) {
	w, err := windowFromQuery(r)
	if err != nil {
		return nil, err
	}
	limit, err := intParam(r, "limit", 0)
	if err != nil {
		return nil, err
	}
	return s.query.ListErrors(r.Context(), identityFrom(r.Context()), r.PathValue("service"), w, r.URL.Query().Get("query"), limit)
}

func (s *Server) getError(r *http.Request) (any, error) {
	return s.query.GetError(r.Context(), identityFrom(r.Context()), r.PathValue("service"), r.URL.Query().Get("env"), r.PathValue("id"))
}

func (s *Server) releases(r *http.Request) (any, error) {
	w, err := windowFromQuery(r)
	if err != nil {
		return nil, err
	}
	return s.query.Releases(r.Context(), identityFrom(r.Context()), r.PathValue("service"), w)
}

func (s *Server) dataSchema(r *http.Request) (any, error) {
	return s.query.DataSchema(r.Context(), identityFrom(r.Context()), r.PathValue("service"), r.URL.Query().Get("env"), r.URL.Query()["entity"])
}

func (s *Server) queryData(r *http.Request) (any, error) {
	var req api.DataQueryRequest
	if err := decodeBody(r, &req); err != nil {
		return nil, err
	}
	return s.query.QueryData(r.Context(), identityFrom(r.Context()), r.PathValue("service"), req)
}
