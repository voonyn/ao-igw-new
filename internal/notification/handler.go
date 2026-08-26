package notification

import (
	"github.com/gofiber/fiber/v3"

	"alphaomega/identitygateway/internal/api/http/middlewares"
	"alphaomega/identitygateway/internal/api/http/response"
)

// The sentinels this domain answers with. A domain registers its own, so no
// other package maps an error it does not declare.
//
// organization.ErrNotFound reaches these routes when an org id names nothing,
// and the organization package already maps it.
//
// A person who administers nothing and a person who administers another
// organization read the same 403 and the same slug. The answer never reports
// which organizations somebody else administers.
func init() {
	response.Map(ErrForbidden, fiber.StatusForbidden, "forbidden", "Forbidden")
	response.Map(ErrUnknownTemplate, fiber.StatusNotFound, "not_found", "Not Found")
	response.Map(ErrTemplateSyntax, fiber.StatusUnprocessableEntity, "invalid_input",
		"The message does not parse. Check the {{ }} placeholders.")
	response.Map(ErrSendFailed, fiber.StatusBadGateway, "send_failed",
		"The transport refused the send.")
}

// Handler serves the delivery settings and the message templates of a tenant to
// the console. It binds the request, calls the service, and writes the envelope.
// No rule lives here.
type Handler struct {
	svc *Service
}

func NewHandler(svc *Service) *Handler {
	return &Handler{svc: svc}
}

// AdminRoutes mounts the notification routes. The caller mounts the tenant
// middleware and the bearer middleware on the group, so every route below reads
// a resolved tenant and a verified subject.
//
// The delivery settings and the test send exist at tenant level only: one relay
// serves the whole tenant. A template exists at two levels, the same paths with
// an organization in front, and an empty organization is the tenant message.
//
// The template lists are bounded — the gateway renders three keys — so they are
// not paged.
func AdminRoutes(router fiber.Router, h *Handler) {
	router.Get("/notifications/settings", h.readSettings)
	router.Patch("/notifications/settings", h.writeSettings)
	router.Post("/notifications/test", h.sendTest)

	router.Get("/notifications/templates", h.listTemplates)
	router.Get("/notifications/templates/:key", h.readTemplate)
	router.Get("/notifications/templates/:key/preview", h.previewTemplate)
	router.Put("/notifications/templates/:key", h.writeTemplate)
	router.Delete("/notifications/templates/:key", h.resetTemplate)

	router.Get("/orgs/:orgId/notifications/templates", h.listTemplates)
	router.Get("/orgs/:orgId/notifications/templates/:key", h.readTemplate)
	router.Get("/orgs/:orgId/notifications/templates/:key/preview", h.previewTemplate)
	router.Put("/orgs/:orgId/notifications/templates/:key", h.writeTemplate)
	router.Delete("/orgs/:orgId/notifications/templates/:key", h.resetTemplate)
}

func (h *Handler) readSettings(c fiber.Ctx) error {
	view, err := h.svc.ReadSettings(c.Context(), actorFrom(c))
	if err != nil {
		return response.Fail(c, err)
	}
	return response.OK(c, view)
}

func (h *Handler) writeSettings(c fiber.Ctx) error {
	var body SettingsBody
	if err := c.Bind().Body(&body); err != nil {
		return response.Validation(c, err)
	}

	view, err := h.svc.WriteSettings(c.Context(), actorFrom(c), body)
	if err != nil {
		return response.Fail(c, err)
	}
	return response.OK(c, view)
}

func (h *Handler) sendTest(c fiber.Ctx) error {
	var body TestBody
	if err := c.Bind().Body(&body); err != nil {
		return response.Validation(c, err)
	}

	if err := h.svc.SendTest(c.Context(), actorFrom(c), body); err != nil {
		return response.Fail(c, err)
	}
	return response.NoContent(c)
}

func (h *Handler) listTemplates(c fiber.Ctx) error {
	rows, err := h.svc.ListTemplates(c.Context(), actorFrom(c), c.Params("orgId"))
	if err != nil {
		return response.Fail(c, err)
	}
	return response.OK(c, rows)
}

func (h *Handler) readTemplate(c fiber.Ctx) error {
	view, err := h.svc.ReadTemplate(c.Context(), actorFrom(c), c.Params("orgId"), c.Params("key"))
	if err != nil {
		return response.Fail(c, err)
	}
	return response.OK(c, view)
}

func (h *Handler) previewTemplate(c fiber.Ctx) error {
	rendered, err := h.svc.PreviewTemplate(c.Context(), actorFrom(c), c.Params("orgId"), c.Params("key"))
	if err != nil {
		return response.Fail(c, err)
	}
	return response.OK(c, rendered)
}

func (h *Handler) writeTemplate(c fiber.Ctx) error {
	var body TemplateBody
	if err := c.Bind().Body(&body); err != nil {
		return response.Validation(c, err)
	}

	view, err := h.svc.WriteTemplate(c.Context(), actorFrom(c), c.Params("orgId"), c.Params("key"), body)
	if err != nil {
		return response.Fail(c, err)
	}
	return response.OK(c, view)
}

func (h *Handler) resetTemplate(c fiber.Ctx) error {
	err := h.svc.ResetTemplate(c.Context(), actorFrom(c), c.Params("orgId"), c.Params("key"))
	if err != nil {
		return response.Fail(c, err)
	}
	return response.NoContent(c)
}

// actorFrom reads the person behind the request. The tenant middleware and the
// bearer guard both ran, so both values are present.
func actorFrom(c fiber.Ctx) Actor { return Actor(middlewares.ActorFrom(c)) }
