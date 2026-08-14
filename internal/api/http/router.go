package http

import (
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/gofiber/fiber/v3/middleware/healthcheck"
	"github.com/gofiber/fiber/v3/middleware/requestid"
	"github.com/uptrace/bun"

	"alphaomega/identitygateway/internal/api/http/response"
	"alphaomega/identitygateway/internal/platform/cache"
	"alphaomega/identitygateway/internal/platform/config"
	"alphaomega/identitygateway/internal/platform/logger"
)

const requestTimeout = 30 * time.Second

func Routes(app *fiber.App, cfg *config.Config, bdb *bun.DB, rdb cache.Client, log logger.Logger) {
	app.Use(requestid.New())

	// rootPath := app.Group("/")

	// healthSvc := handler.NewHealthCheckService(bdb, rdb, cfg, log)
	// handler.HealthCheckRoutes(rootPath, healthSvc)

	healthCheckHandler(app)
	// const oidcPrefix = "/oidc/v1"

	// reg := mountOIDC(rootPath, oidcPrefix, cfg, bdb, rdb, log, auditRec)

	// mountLogin(rootPath, "/api/v1/login", oidcPrefix, cfg, bdb, rdb, log, auditRec)

	// mountAccount(rootPath, "/api/v1/account", cfg, bdb, rdb, log, auditRec)
}

func healthCheckHandler(app *fiber.App) {
	app.Get(healthcheck.LivenessEndpoint, healthcheck.New())
	app.Get(healthcheck.ReadinessEndpoint, healthcheck.New())
	app.Get(healthcheck.StartupEndpoint, healthcheck.New())
}

func NotFoundHandler(c fiber.Ctx) error {
	return response.Error(c, fiber.StatusNotFound, "Not Found", nil)
}
