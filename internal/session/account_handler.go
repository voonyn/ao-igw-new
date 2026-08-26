package session

import (
	"github.com/gofiber/fiber/v3"

	"alphaomega/identitygateway/internal/api/http/response"
)

// AccountHandler serves a person their own login sessions. It binds the request,
// calls the service, and writes the envelope. No rule lives here.
type AccountHandler struct {
	svc *AccountService
}

func NewAccountHandler(svc *AccountService) *AccountHandler {
	return &AccountHandler{svc: svc}
}

// AccountRoutes mounts the self-service session routes. The caller mounts the
// tenant middleware and the bearer guard on the group, so every route below
// reads a resolved tenant and a verified subject.
//
// The list is bounded and pages nothing: a person holds one login session per
// device, and the whole list fits one answer.
//
// The two revokes are one path apart on purpose. A named session ends that
// session, and the collection ends every session the caller holds except the one
// the query names.
func AccountRoutes(router fiber.Router, h *AccountHandler) {
	router.Get("/sessions", h.list)
	router.Delete("/sessions", h.revokeOthers)
	router.Delete("/sessions/:id", h.revoke)
}

// list answers the live login sessions of the caller. It marks none of them as
// the caller's own: the portal reads sid from the ID token it holds and marks
// the row itself.
func (h *AccountHandler) list(c fiber.Ctx) error {
	views, err := h.svc.List(c.Context(), actorFrom(c))
	if err != nil {
		return response.Fail(c, err)
	}
	return response.OK(c, views)
}

func (h *AccountHandler) revoke(c fiber.Ctx) error {
	view, err := h.svc.Revoke(c.Context(), actorFrom(c), c.Params("id"))
	if err != nil {
		return response.Fail(c, err)
	}
	return response.OK(c, view)
}

// revokeOthers ends every login session of the caller except the one the except
// query parameter names. With no session named, it ends every one of them.
func (h *AccountHandler) revokeOthers(c fiber.Ctx) error {
	view, err := h.svc.RevokeOthers(c.Context(), actorFrom(c), c.Query("except"))
	if err != nil {
		return response.Fail(c, err)
	}
	return response.OK(c, view)
}
