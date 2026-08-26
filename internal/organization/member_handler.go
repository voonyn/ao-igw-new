package organization

import (
	"github.com/gofiber/fiber/v3"
	"github.com/gofiber/fiber/v3/middleware/paginate"

	"alphaomega/identitygateway/internal/api/http/middlewares"
	"alphaomega/identitygateway/internal/api/http/response"
)

// The sentinels the membership half of this domain answers with. ErrNotAdmin
// and ErrForbidden are registered beside the organization routes, so a refused
// membership write reads the same 403 and the same slug as any other.
//
// A refused grant of ORG_OWNER reads that same answer too. The response never
// reports which seats somebody else holds.
func init() {
	response.Map(ErrMemberNotFound, fiber.StatusNotFound, "not_found", "Not Found")
	response.Map(ErrOwnerGrant, fiber.StatusForbidden, "forbidden", "Forbidden")
	response.Map(ErrUnknownRole, fiber.StatusUnprocessableEntity, "invalid_input",
		"That role does not exist at this level.")
	response.Map(ErrLastOwner, fiber.StatusConflict, "last_owner",
		"The tenant must keep one IAM_OWNER. Grant the role to somebody else first.")
}

// MemberHandler serves the two rosters of a tenant. It binds the request, calls
// the service, and writes the envelope. No rule lives here.
type MemberHandler struct {
	svc *MemberService
}

func NewMemberHandler(svc *MemberService) *MemberHandler {
	return &MemberHandler{svc: svc}
}

// MemberRoutes mounts the membership routes. The caller mounts the tenant
// middleware and the bearer middleware on the group, so every route below reads
// a resolved tenant and a verified subject.
//
// Both rosters sort by the one column the console offers. Any other key is
// refused with 422.
//
// One write serves both rosters. The body names the organization, and an empty
// name means the tenant, which is the shape the console already sends.
func MemberRoutes(router fiber.Router, h *MemberHandler) {
	router.Get("/members/tenant", middlewares.Paginate("created"), h.listTenant)
	router.Get("/members/org", middlewares.Paginate("created"), h.listOrg)
	router.Post("/members", h.add)
	router.Patch("/members/:userId", h.updateRoles)
	router.Delete("/members/:userId", h.remove)
}

func (h *MemberHandler) listTenant(c fiber.Ctx) error {
	desc, limit, offset := pageFrom(c)

	rows, total, err := h.svc.ListTenant(c.Context(), actorFrom(c), desc, limit, offset)
	if err != nil {
		return response.Fail(c, err)
	}
	return response.List(c, rows, total)
}

func (h *MemberHandler) listOrg(c fiber.Ctx) error {
	desc, limit, offset := pageFrom(c)

	rows, total, err := h.svc.ListOrg(c.Context(), actorFrom(c), c.Query("orgId"), desc, limit, offset)
	if err != nil {
		return response.Fail(c, err)
	}
	return response.List(c, rows, total)
}

func (h *MemberHandler) add(c fiber.Ctx) error {
	var body MemberBody
	if err := c.Bind().Body(&body); err != nil {
		return response.Validation(c, err)
	}

	if err := h.svc.Add(c.Context(), actorFrom(c), body); err != nil {
		return response.Fail(c, err)
	}
	return response.NoContent(c)
}

func (h *MemberHandler) updateRoles(c fiber.Ctx) error {
	var body RolesBody
	if err := c.Bind().Body(&body); err != nil {
		return response.Validation(c, err)
	}

	if err := h.svc.UpdateRoles(c.Context(), actorFrom(c), c.Params("userId"), body); err != nil {
		return response.Fail(c, err)
	}
	return response.NoContent(c)
}

// remove reads the organization from the query, because a delete carries no
// body. An absent orgId names the tenant roster, the same way an empty one in a
// body does.
func (h *MemberHandler) remove(c fiber.Ctx) error {
	err := h.svc.Remove(c.Context(), actorFrom(c), c.Params("userId"), c.Query("orgId"))
	if err != nil {
		return response.Fail(c, err)
	}
	return response.NoContent(c)
}

// pageFrom reads the window one roster read asks for. The paginate middleware
// already clamped the limit and refused an unknown sort key, and both rosters
// sort by their one column, so only the direction is read here.
func pageFrom(c fiber.Ctx) (desc bool, limit, offset int) {
	// A read that asks for no order reads newest first, the way every other
	// admin list does.
	key, down := middlewares.SortFrom(c)
	desc = key == "" || down

	limit = 1
	if info, ok := paginate.FromContext(c); ok && info != nil {
		limit, offset = info.Limit, info.Start()
	}
	return desc, limit, offset
}
