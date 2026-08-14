package handler

import (
	"context"
	"fmt"
	"runtime"
	"strings"
	"time"

	"alphaomega/identitygateway/internal/api/http/response"
	"alphaomega/identitygateway/internal/platform/cache"
	"alphaomega/identitygateway/internal/platform/config"
	"alphaomega/identitygateway/internal/platform/db"
	"alphaomega/identitygateway/internal/platform/logger"

	"github.com/gofiber/fiber/v3"
	"github.com/uptrace/bun"
)

// ─────────────────────────────────────────────────────────────────────────────
// Health checks (old repo: internal/service/health_check_service.go)
//
// The probes live in the handler package rather than a domain package: they
// check process and infrastructure liveness (DB, cache, migrations, config,
// heap, goroutines), not any identity domain. The routes that assemble them into
// a status list — /health, /healthz/live, /healthz/ready, /ping — follow at the
// bottom of this file (old repo: internal/router/health_check_route.go).
// ─────────────────────────────────────────────────────────────────────────────

// goroutineThreshold guards against goroutine leaks in the liveness probe.
// A healthy gateway runs well under this; crossing it signals a leak.
const goroutineThreshold = 10000

// HealthCheckService runs the per-dependency readiness/liveness probes the
// health endpoint assembles into a status list (DB, cache, migrations, config,
// heap, goroutines) plus version/uptime. Single implementation; the router holds
// it directly.
type HealthCheckService struct {
	log       logger.Logger
	db        *bun.DB
	cache     cache.Client
	cfg       *config.Config
	startedAt time.Time
}

func NewHealthCheckService(bdb *bun.DB, rdb cache.Client, cfg *config.Config, log logger.Logger) *HealthCheckService {
	return &HealthCheckService{
		db:        bdb,
		cache:     rdb,
		cfg:       cfg,
		startedAt: time.Now(),
		log:       log,
	}
}

// Version returns the running application version.
func (s *HealthCheckService) Version() string {
	return s.cfg.App.Version
}

// Uptime returns how long the service has been running since startup.
func (s *HealthCheckService) Uptime() time.Duration {
	return time.Since(s.startedAt)
}

func (s *HealthCheckService) DBCheck() error {
	if err := s.db.Ping(); err != nil {
		s.log.Error("Failed to ping the database", logger.Err(err))
		return err
	}
	return nil
}

func (s *HealthCheckService) CacheCheck() error {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	if err := s.cache.Ping(ctx); err != nil {
		s.log.Error("Failed to ping the cache", logger.Err(err))
		return err
	}
	return nil
}

// MigrationCheck verifies the database schema is fully migrated.
func (s *HealthCheckService) MigrationCheck() error {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	if err := db.MigrationStatus(ctx, s.db); err != nil {
		s.log.Error("Database migrations not up to date", logger.Err(err))
		return err
	}
	return nil
}

// ConfigCheck verifies that required configuration and secrets are loaded.
func (s *HealthCheckService) ConfigCheck() error {
	var missing []string

	if s.cfg.Database.EncryptionKey == "" {
		missing = append(missing, "database.encryption_key")
	}

	// The login UI PAT is mandatory outside development; without it every
	// /v1/authn/* request fails, so the service is not truly ready.
	if !s.cfg.App.IsDevelopment() && len(s.cfg.Auth.LoginPATs()) == 0 {
		missing = append(missing, "auth.login_ui_pat")
	}

	if len(missing) > 0 {
		err := fmt.Errorf("required configuration missing: %s", strings.Join(missing, ", "))
		s.log.Error("Configuration not fully loaded", logger.Err(err))
		return err
	}
	return nil
}

// GoroutineCheck flags a likely goroutine leak when the live goroutine
// count crosses goroutineThreshold. Cheap enough for the liveness probe.
func (s *HealthCheckService) GoroutineCheck() error {
	n := runtime.NumGoroutine()
	if n > goroutineThreshold {
		s.log.Error("Goroutine count exceeds threshold",
			logger.Int("count", n),
			logger.Int("threshold", goroutineThreshold),
		)
		return fmt.Errorf("possible goroutine leak: %d goroutines (threshold %d)", n, goroutineThreshold)
	}
	return nil
}

func formatBytes(b uint64) string {
	const (
		KB = 1024
		MB = 1024 * KB
		GB = 1024 * MB
	)
	switch {
	case b >= GB:
		return fmt.Sprintf("%.2f GB", float64(b)/GB)
	case b >= MB:
		return fmt.Sprintf("%.2f MB", float64(b)/MB)
	case b >= KB:
		return fmt.Sprintf("%.2f KB", float64(b)/KB)
	default:
		return fmt.Sprintf("%d B", b)
	}
}

func (s *HealthCheckService) MemoryHeapCheck() error {
	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)

	heapAlloc := memStats.HeapAlloc
	heapThreshold := uint64(300 * 1024 * 1024)

	s.log.Info("Heap memory allocation",
		logger.String("allocated", formatBytes(heapAlloc)),
		logger.String("threshold", formatBytes(heapThreshold)),
	)

	if heapAlloc > heapThreshold {
		s.log.Error("Heap memory usage exceeds threshold",
			logger.String("allocated", formatBytes(heapAlloc)),
			logger.String("threshold", formatBytes(heapThreshold)),
		)
		return fmt.Errorf("heap memory usage too high: %s used, threshold is %s", formatBytes(heapAlloc), formatBytes(heapThreshold))
	}
	return nil
}

// ─────────────────────────────────────────────────────────────────────────────
// Health routes (old repo: internal/router/health_check_route.go)
// ─────────────────────────────────────────────────────────────────────────────

// healthCheckRouter holds the dependency for the health/liveness/readiness
// probes. It binds the request and shapes the response; all checks come from the
// service.
type healthCheckRouter struct {
	svc *HealthCheckService
}

// HealthCheckRoutes mounts the health, liveness, readiness, and ping probes.
func HealthCheckRoutes(rootPath fiber.Router, h *HealthCheckService) {
	hr := &healthCheckRouter{svc: h}

	rootPath.Get("/health", hr.check)
	rootPath.Get("/healthz/live", hr.live)
	rootPath.Get("/healthz/ready", hr.ready)
	rootPath.Get("/ping", hr.ping)
}

// checkUnavailable is the generic per-dependency message shown to unauthenticated
// health callers in place of the raw internal error.
const checkUnavailable = "dependency unavailable"

// namedCheck pairs a dependency name with the probe that verifies it.
type namedCheck struct {
	name string
	fn   func() error
}

func (hr *healthCheckRouter) addServiceStatus(
	serviceList *[]response.HealthCheck, name string, isUp bool, message *string,
) {
	status := "Up"

	if !isUp {
		status = "Down"
	}

	*serviceList = append(*serviceList, response.HealthCheck{
		Name:    name,
		Status:  status,
		IsUp:    isUp,
		Message: message,
	})
}

// runChecks executes each check, recording its status in serviceList, and
// returns false if any check failed.
func (hr *healthCheckRouter) runChecks(serviceList *[]response.HealthCheck, checks []namedCheck) bool {
	ok := true
	for _, chk := range checks {
		if err := chk.fn(); err != nil {
			ok = false
			// These probes are unauthenticated: never surface the raw internal
			// error (driver text, DSN/host fragments, missing-config key names) to
			// the caller. The service already logged the full error server-side.
			msg := checkUnavailable
			hr.addServiceStatus(serviceList, chk.name, false, &msg)
		} else {
			hr.addServiceStatus(serviceList, chk.name, true, nil)
		}
	}
	return ok
}

func (hr *healthCheckRouter) ping(c fiber.Ctx) error {
	return c.Status(fiber.StatusOK).SendString("pong")
}

// @Tags Health
// @Summary Health Overview
// @Description Overall service health: uptime, build info, and a summary of critical dependencies (database, cache).
// @Accept json
// @Produce json
// @Success 200 {object} response.HealthCheckResponse
// @Failure 503 {object} response.HealthCheckResponse
// @Router /health [get]
func (hr *healthCheckRouter) check(c fiber.Ctx) error {
	var serviceList []response.HealthCheck

	// Summary status of critical dependencies.
	isHealthy := hr.runChecks(&serviceList, []namedCheck{
		{"Database", hr.svc.DBCheck},
		{"Cache", hr.svc.CacheCheck},
	})

	statusCode := fiber.StatusOK
	status := "healthy"
	message := "Service is healthy"

	if !isHealthy {
		statusCode = fiber.StatusServiceUnavailable
		status = "unhealthy"
		message = "One or more critical dependencies are down"
	}

	return c.Status(statusCode).JSON(response.HealthCheckResponse{
		Code:      statusCode,
		Status:    status,
		Message:   message,
		Version:   hr.svc.Version(),
		Uptime:    hr.svc.Uptime().Round(time.Second).String(),
		IsHealthy: isHealthy,
		Result:    serviceList,
	})
}

// @Tags Health
// @Summary Liveness Probe
// @Description Lightweight check that the process is alive (memory not exhausted, no goroutine leak). Does NOT touch external dependencies.
// @Accept json
// @Produce json
// @Success 200 {object} response.HealthCheckResponse
// @Failure 503 {object} response.HealthCheckResponse
// @Router /healthz/live [get]
func (hr *healthCheckRouter) live(c fiber.Ctx) error {
	var serviceList []response.HealthCheck

	isAlive := hr.runChecks(&serviceList, []namedCheck{
		{"Memory", hr.svc.MemoryHeapCheck},
		{"Goroutines", hr.svc.GoroutineCheck},
	})

	statusCode := fiber.StatusOK
	status := "success"
	message := "Service is alive"

	if !isAlive {
		statusCode = fiber.StatusServiceUnavailable
		status = "error"
		message = "Service is not alive"
	}

	return c.Status(statusCode).JSON(response.HealthCheckResponse{
		Code:      statusCode,
		Status:    status,
		Message:   message,
		IsHealthy: isAlive,
		Result:    serviceList,
	})
}

// @Tags Health
// @Summary Readiness Probe
// @Description Reports whether the service can serve traffic by checking all dependencies: database, cache, migrations, and required configuration.
// @Accept json
// @Produce json
// @Success 200 {object} response.HealthCheckResponse
// @Failure 503 {object} response.HealthCheckResponse
// @Router /healthz/ready [get]
func (hr *healthCheckRouter) ready(c fiber.Ctx) error {
	var serviceList []response.HealthCheck

	isReady := hr.runChecks(&serviceList, []namedCheck{
		{"Database", hr.svc.DBCheck},
		{"Cache", hr.svc.CacheCheck},
		{"Migrations", hr.svc.MigrationCheck},
		{"Config", hr.svc.ConfigCheck},
	})

	statusCode := fiber.StatusOK
	status := "success"
	message := "Service is ready"

	if !isReady {
		statusCode = fiber.StatusServiceUnavailable
		status = "error"
		message = "Service is not ready"
	}

	return c.Status(statusCode).JSON(response.HealthCheckResponse{
		Code:      statusCode,
		Status:    status,
		Message:   message,
		IsHealthy: isReady,
		Result:    serviceList,
	})
}
