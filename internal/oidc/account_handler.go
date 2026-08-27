package oidc

import (
	"github.com/gofiber/fiber/v3"

	"alphaomega/identitygateway/internal/api/http/response"
)

// A disconnect of a client the caller never connected answers 404. A consent of
// somebody else answers the same way, so the refusal never says which
// applications another person connected.
func init() {
	response.Map(ErrConsentNotFound, fiber.StatusNotFound, "not_found", "Not Found")
}

// AccountActorReader reads the person behind one self-service request.
//
// The tenant middleware and the bearer guard put both values on the request, and
// this package cannot read them back itself: internal/api/http/middlewares
// imports this package for the provider config of the resolved tenant, so
// importing it here would close the cycle. The router therefore passes the
// reader in.
type AccountActorReader func(c fiber.Ctx) AccountActor

// AccountHandler serves a person the applications that hold their consent. It
// reads the request, calls the service, and writes the envelope. No rule lives
// here.
type AccountHandler struct {
	svc   *AccountService
	actor AccountActorReader
}

func NewAccountHandler(svc *AccountService, actor AccountActorReader) *AccountHandler {
	return &AccountHandler{svc: svc, actor: actor}
}

// AccountRoutes mounts the connected application routes. The caller mounts the
// tenant middleware and the bearer guard on the group, so both routes below read
// a resolved tenant and a verified subject.
//
// The addresses are the ones the portal calls. The portal defines the contract
// here: it is a complete front end, and this API is built to match it.
//
// The list is bounded and pages nothing: it holds one row per application the
// person connected, and the whole list fits one answer.
func AccountRoutes(router fiber.Router, h *AccountHandler) {
	router.Get("/connected-apps", h.list)
	router.Delete("/connected-apps/:clientId", h.disconnect)
}

func (h *AccountHandler) list(c fiber.Ctx) error {
	views, err := h.svc.List(c.Context(), h.actor(c))
	if err != nil {
		return response.Fail(c, err)
	}
	return response.OK(c, views)
}

func (h *AccountHandler) disconnect(c fiber.Ctx) error {
	view, err := h.svc.Disconnect(c.Context(), h.actor(c), c.Params("clientId"))
	if err != nil {
		return response.Fail(c, err)
	}
	return response.OK(c, view)
}
