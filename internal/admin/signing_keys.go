package admin

import (
	"errors"
	"net/http"

	"github.com/contember/sonda/internal/issuer"
)

const signingKeysLead = "Keys of Sonda's own OIDC identity. Relying parties such as AWS verify its tokens against every key listed here."

func (h *Handler) listSigningKeys(w http.ResponseWriter, r *http.Request) {
	h.renderSigningKeys(w, r, http.StatusOK, "")
}

func (h *Handler) renderSigningKeys(w http.ResponseWriter, r *http.Request, status int, message string) {
	keys, err := h.issuer.Keys(r.Context())
	if err != nil {
		h.serverError(w, err)
		return
	}
	h.render(w, r, status, "signing-keys", view{Title: "Signing keys", Lead: signingKeysLead, Nav: "signing-keys", Error: message, Data: keys})
}

func (h *Handler) addSigningKey(w http.ResponseWriter, r *http.Request) {
	id, err := h.issuer.AddKey(r.Context())
	if err != nil {
		h.serverError(w, err)
		return
	}
	h.log.Info("signing key added", "kid", id)
	redirect(w, r, "/admin/signing-keys")
}

func (h *Handler) removeSigningKey(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	err := h.issuer.RemoveKey(r.Context(), id)
	switch {
	case errors.Is(err, issuer.ErrKeyInUse):
		h.renderSigningKeys(w, r, http.StatusUnprocessableEntity, "Key "+id+" is in use: Sonda signs with the newest key and with the key this process started with. Add a newer key and restart every replica first.")
		return
	case errors.Is(err, issuer.ErrKeyNotFound):
		redirect(w, r, "/admin/signing-keys")
		return
	case err != nil:
		h.serverError(w, err)
		return
	}
	h.log.Info("signing key removed", "kid", id)
	redirect(w, r, "/admin/signing-keys")
}
