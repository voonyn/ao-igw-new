package qrlogin

import (
	"strings"

	"github.com/gofiber/fiber/v3"

	"alphaomega/identitygateway/internal/api/http/middlewares"
	"alphaomega/identitygateway/internal/api/http/response"
)

// bearerPrefix is how the sign-in front end presents the login session token.
const bearerPrefix = "Bearer "

// The sentinel this domain answers with. A body that names no transaction is the
// one callback failure a caller can observe.
func init() {
	response.Map(ErrUnusableCallback, fiber.StatusBadRequest, "invalid_request", "Bad Request")
}

// Handler serves the three steps of QR Login. It binds the request, calls the
// service, and writes the envelope. No rule lives here.
type Handler struct {
	svc *Service
}

func NewHandler(svc *Service) *Handler {
	return &Handler{svc: svc}
}

// Routes mounts the two steps the browser drives. The caller mounts the login
// credential of the front end and the tenant middleware on the group, the same
// way it mounts them on the other login steps.
func Routes(router fiber.Router, h *Handler) {
	router.Use(requireTenant)
	router.Post("/start", h.start)
	router.Post("/poll", h.poll)
}

// CallbackRoute mounts the push callback of the Scan Verifier. It sits outside
// every group above: the push carries its own credential, and it reaches one
// fixed address whose host names no tenant.
func CallbackRoute(router fiber.Router, path string, credential fiber.Handler, h *Handler) {
	router.Post(path, credential, h.callback)
}

// requireTenant answers a request that reached a QR Login route with no resolved
// tenant. Both routes below read the tenant, so the check lives here once.
func requireTenant(c fiber.Ctx) error {
	if _, ok := middlewares.TenantFrom(c); !ok {
		return response.Error(c, fiber.StatusNotFound, "Not Found", nil)
	}
	return c.Next()
}

// start opens a transaction with the Scan Verifier and hands the browser the
// login session token with the code object of the verifier, unchanged.
func (h *Handler) start(c fiber.Ctx) error {
	tc, _ := middlewares.TenantFrom(c)

	started, err := h.svc.Start(c.Context(), tc.TenantID, metaFrom(c))
	if err != nil {
		return response.Fail(c, err)
	}

	return response.OK(c, StartResponse{
		SessionID:    started.SessionID,
		SessionToken: started.SessionToken,
		QRCode:       started.QRCode,
		ExpiresIn:    started.ExpiresIn,
	})
}

// poll reports the state of the transaction and, on the step to authenticated,
// returns the rotated login session token exactly once.
func (h *Handler) poll(c fiber.Ctx) error {
	tc, _ := middlewares.TenantFrom(c)

	token := bearerToken(c)
	if token == "" {
		return response.Error(c, fiber.StatusUnauthorized, "Unauthorized", nil)
	}

	polled, err := h.svc.Poll(c.Context(), tc.TenantID, token, metaFrom(c))
	if err != nil {
		return response.Fail(c, err)
	}

	return response.OK(c, PollResponse{Status: polled.Status, SessionToken: polled.SessionToken})
}

// callback takes the push of the Scan Verifier.
//
// The body reaches the service as raw bytes. The contract belongs to a third
// party, so its shape is understood in one place, parseCallback, and not half in
// a request struct here.
//
// Everything the service tolerates answers the same 200. Only a body that names
// no transaction at all is refused.
func (h *Handler) callback(c fiber.Ctx) error {
	if err := h.svc.Callback(c.Context(), c.Body(), metaFrom(c)); err != nil {
		return response.Fail(c, err)
	}
	return response.OK(c, CallbackResponse{Status: "ok"})
}

// metaFrom reads the address and the agent of the request for the audit trail.
func metaFrom(c fiber.Ctx) Meta {
	return Meta{IP: c.IP(), UserAgent: c.Get(fiber.HeaderUserAgent)}
}

// bearerToken reads the login session token off the Authorization header. The
// token is a credential, so the caller never logs the value.
func bearerToken(c fiber.Ctx) string {
	header := c.Get(fiber.HeaderAuthorization)
	if len(header) <= len(bearerPrefix) || !strings.EqualFold(header[:len(bearerPrefix)], bearerPrefix) {
		return ""
	}
	return strings.TrimSpace(header[len(bearerPrefix):])
}
