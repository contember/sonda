package admin

import (
	"net/http"
	"strconv"

	"github.com/contember/sonda/internal/store"
)

const auditPageSize = 100

type auditPage struct {
	Identity   string
	Identities []string
	Records    []store.AuditRecord
	// OlderID is the cursor of the next page, or 0 on the last page.
	OlderID int64
}

func (h *Handler) auditLog(w http.ResponseWriter, r *http.Request) {
	filter := store.AuditFilter{Identity: r.URL.Query().Get("identity"), Limit: auditPageSize}
	if before := r.URL.Query().Get("before"); before != "" {
		id, err := strconv.ParseInt(before, 10, 64)
		if err != nil || id <= 0 {
			http.Error(w, "before must be a positive integer", http.StatusBadRequest)
			return
		}
		filter.BeforeID = id
	}
	records, err := h.store.ListAudit(r.Context(), filter)
	if err != nil {
		h.serverError(w, err)
		return
	}
	list, err := h.identities.List(r.Context())
	if err != nil {
		h.serverError(w, err)
		return
	}
	page := auditPage{Identity: filter.Identity, Identities: []string{auditIdentity}, Records: records}
	for _, identity := range list {
		page.Identities = append(page.Identities, identity.Name)
	}
	if len(records) == auditPageSize {
		page.OlderID = records[len(records)-1].ID
	}
	h.render(w, http.StatusOK, "audit", view{Title: "Audit log", Lead: "Every agent request and admin action, newest first.", Nav: "audit", Data: page})
}
