package oidc

import (
	"github.com/gofiber/fiber/v3"

	"alphaomega/identitygateway/internal/api/http/response"
)

// The sentinels the scope routes answer with. ErrForbidden is registered by the
// grant service of this domain, so it is not registered again here.
//
// Three of the slugs are named by the console, and each one is a sentence the
// operator can act on: protected_claim names a claim they must rename,
// scope_in_use names a client they must edit first, and limit_exceeded names a
// size they must reduce.
func init() {
	response.Map(ErrScopeNotFound, fiber.StatusNotFound, "not_found", "Not Found")
	response.Map(ErrMapperNotFound, fiber.StatusNotFound, "not_found", "Not Found")

	response.Map(ErrScopeNameTaken, fiber.StatusConflict, "name_conflict",
		"The tenant already holds a scope with that name.")
	response.Map(ErrClaimTaken, fiber.StatusConflict, "name_conflict",
		"The scope already releases a claim with that name.")

	response.Map(ErrBuiltinScope, fiber.StatusConflict, "builtin_scope",
		"A builtin scope cannot be deleted. Disable it instead.")
	response.Map(ErrScopeInUse, fiber.StatusConflict, "scope_in_use",
		"A client still holds this scope.")

	response.Map(ErrProtectedClaim, fiber.StatusUnprocessableEntity, "protected_claim",
		"That claim name is reserved and cannot be written.")
	response.Map(ErrLimitExceeded, fiber.StatusUnprocessableEntity, "limit_exceeded",
		"The limit of this scope is exceeded.")
}

// ScopeAdminHandler serves the scope registry and the claim mappers of a tenant
// to the console. It binds the request, calls the service, and writes the
// envelope. No rule lives here.
//
// It reads the caller through the same reader the provider handler takes. See
// AdminActorReader for why this package cannot read the request itself.
type ScopeAdminHandler struct {
	svc   *ScopeAdminService
	actor AdminActorReader
}

func NewScopeAdminHandler(
	svc *ScopeAdminService, actor AdminActorReader,
) *ScopeAdminHandler {
	return &ScopeAdminHandler{svc: svc, actor: actor}
}

// ScopeAdminRoutes mounts the scope routes. The caller mounts the tenant
// middleware and the bearer middleware on the group, so every route below reads
// a resolved tenant and a verified subject.
//
// Neither list is paged. The registry is bounded by what an operator writes, and
// the claims of one scope are bounded by MaxMappersPerScope.
//
// A claim mapper is addressed by its own id, without the scope, because the
// console edits a claim from a row it already read.
func ScopeAdminRoutes(router fiber.Router, h *ScopeAdminHandler) {
	router.Get("/scopes", h.listScopes)
	router.Post("/scopes", h.createScope)
	router.Patch("/scopes/:id", h.updateScope)
	router.Delete("/scopes/:id", h.deleteScope)

	router.Get("/scopes/:id/mappers", h.listMappers)
	router.Post("/scopes/:id/mappers", h.createMapper)
	router.Patch("/mappers/:id", h.updateMapper)
	router.Delete("/mappers/:id", h.deleteMapper)
}

func (h *ScopeAdminHandler) listScopes(c fiber.Ctx) error {
	views, err := h.svc.ListScopes(c.Context(), h.actor(c))
	if err != nil {
		return response.Fail(c, err)
	}
	return response.OK(c, views)
}

func (h *ScopeAdminHandler) createScope(c fiber.Ctx) error {
	var body ScopeBody
	if err := c.Bind().Body(&body); err != nil {
		return response.Validation(c, err)
	}

	view, err := h.svc.CreateScope(c.Context(), h.actor(c), body)
	if err != nil {
		return response.Fail(c, err)
	}
	return response.Created(c, view)
}

func (h *ScopeAdminHandler) updateScope(c fiber.Ctx) error {
	var body ScopeBody
	if err := c.Bind().Body(&body); err != nil {
		return response.Validation(c, err)
	}

	view, err := h.svc.UpdateScope(c.Context(), h.actor(c), c.Params("id"), body)
	if err != nil {
		return response.Fail(c, err)
	}
	return response.OK(c, view)
}

func (h *ScopeAdminHandler) deleteScope(c fiber.Ctx) error {
	if err := h.svc.DeleteScope(c.Context(), h.actor(c), c.Params("id")); err != nil {
		return response.Fail(c, err)
	}
	return response.NoContent(c)
}

func (h *ScopeAdminHandler) listMappers(c fiber.Ctx) error {
	views, err := h.svc.ListMappers(c.Context(), h.actor(c), c.Params("id"))
	if err != nil {
		return response.Fail(c, err)
	}
	return response.OK(c, views)
}

func (h *ScopeAdminHandler) createMapper(c fiber.Ctx) error {
	var body MapperBody
	if err := c.Bind().Body(&body); err != nil {
		return response.Validation(c, err)
	}

	view, err := h.svc.CreateMapper(c.Context(), h.actor(c), c.Params("id"), body)
	if err != nil {
		return response.Fail(c, err)
	}
	return response.Created(c, view)
}

func (h *ScopeAdminHandler) updateMapper(c fiber.Ctx) error {
	var body MapperBody
	if err := c.Bind().Body(&body); err != nil {
		return response.Validation(c, err)
	}

	view, err := h.svc.UpdateMapper(c.Context(), h.actor(c), c.Params("id"), body)
	if err != nil {
		return response.Fail(c, err)
	}
	return response.OK(c, view)
}

func (h *ScopeAdminHandler) deleteMapper(c fiber.Ctx) error {
	if err := h.svc.DeleteMapper(c.Context(), h.actor(c), c.Params("id")); err != nil {
		return response.Fail(c, err)
	}
	return response.NoContent(c)
}
