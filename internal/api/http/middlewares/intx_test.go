package middlewares

import (
	"context"
	"errors"
	"net/http/httptest"
	"testing"

	"github.com/gofiber/fiber/v3"
	"github.com/uptrace/bun"
	"go.uber.org/zap/zapcore"

	"alphaomega/identitygateway/internal/platform/db"
	"alphaomega/identitygateway/internal/platform/logger"
)

// recordingRunner stands in for the transaction manager. The test has no
// database, so it records what the unit of work returned: a nil means commit,
// and anything else means rollback.
type recordingRunner struct {
	ran      bool
	rollback bool
}

func (r *recordingRunner) run(ctx context.Context, fn func(context.Context) error) error {
	r.ran = true
	err := fn(ctx)
	r.rollback = err != nil
	return err
}

// txApp mounts the middleware in front of one handler.
func txApp(t *testing.T, runner *recordingRunner, handler fiber.Handler) *fiber.App {
	t.Helper()

	log, _ := logger.NewObserved()
	app := fiber.New()
	app.Get("/x", InTx(runner.run, log), handler)
	return app
}

// openingRunner stands in for the transaction manager that opened one. It puts
// the transaction on the context the way db.TxManager does, so the middleware
// has one to move onto the second carrier.
func openingRunner(tx bun.Tx) db.TxRunner {
	return func(ctx context.Context, fn func(context.Context) error) error {
		return fn(context.WithValue(ctx, db.TxKey(), tx))
	}
}

// TestInTxCarriesTheTransactionToTheSecondCarrier covers the hop the middleware
// exists for. The adaptor hands the protocol engine a fasthttp request context
// rather than the Go one, so a repository reached that way must still find the
// transaction. The assertion calls db.TxFrom on the fasthttp context, which is
// exactly what db.Conn does inside a repository.
func TestInTxCarriesTheTransactionToTheSecondCarrier(t *testing.T) {
	log, _ := logger.NewObserved()

	var found bool
	app := fiber.New()
	app.Get("/x", InTx(openingRunner(bun.Tx{}), log), func(c fiber.Ctx) error {
		_, found = db.TxFrom(c.RequestCtx())
		return c.SendString("ok")
	})

	answer, err := app.Test(httptest.NewRequest(fiber.MethodGet, "/x", nil))
	if err != nil {
		t.Fatalf("test request: %v", err)
	}
	defer answer.Body.Close()

	if !found {
		t.Error("the fasthttp context does not carry the transaction")
	}
}

// TestInTxLogsAnEmptySecondCarrier covers the transaction that never arrived.
// The middleware then leaves the second carrier empty, and the protocol engine
// writes outside the transaction. Nothing later reveals that, so the middleware
// says so itself.
func TestInTxLogsAnEmptySecondCarrier(t *testing.T) {
	log, logs := logger.NewObserved()
	runner := &recordingRunner{}

	app := fiber.New()
	app.Get("/x", InTx(runner.run, log), func(c fiber.Ctx) error {
		return c.SendString("ok")
	})

	answer, err := app.Test(httptest.NewRequest(fiber.MethodGet, "/x", nil))
	if err != nil {
		t.Fatalf("test request: %v", err)
	}
	defer answer.Body.Close()

	if got := logs.FilterLevelExact(zapcore.ErrorLevel).Len(); got != 1 {
		t.Errorf("the middleware logged %d errors, want 1", got)
	}
}

// TestInTxCommitsOnASuccess covers the answered request. The work returns nil,
// so the transaction commits.
func TestInTxCommitsOnASuccess(t *testing.T) {
	runner := &recordingRunner{}
	app := txApp(t, runner, func(c fiber.Ctx) error {
		return c.SendString("ok")
	})

	answer, err := app.Test(httptest.NewRequest(fiber.MethodGet, "/x", nil))
	if err != nil {
		t.Fatalf("test request: %v", err)
	}
	defer answer.Body.Close()

	if !runner.ran {
		t.Fatal("the middleware did not open a transaction")
	}
	if runner.rollback {
		t.Error("a 200 rolled the transaction back")
	}
	if answer.StatusCode != fiber.StatusOK {
		t.Errorf("the status is %d, want %d", answer.StatusCode, fiber.StatusOK)
	}
}

// TestInTxRollsBackOnARefusal covers the request the protocol engine refused.
// The engine writes its own 400 and returns no error, so the status is the only
// signal that nothing must be kept.
func TestInTxRollsBackOnARefusal(t *testing.T) {
	runner := &recordingRunner{}
	app := txApp(t, runner, func(c fiber.Ctx) error {
		return c.Status(fiber.StatusBadRequest).SendString(`{"error":"invalid_grant"}`)
	})

	answer, err := app.Test(httptest.NewRequest(fiber.MethodGet, "/x", nil))
	if err != nil {
		t.Fatalf("test request: %v", err)
	}
	defer answer.Body.Close()

	if !runner.rollback {
		t.Error("a 400 did not roll the transaction back")
	}
	if answer.StatusCode != fiber.StatusBadRequest {
		t.Errorf("the status is %d, want %d", answer.StatusCode, fiber.StatusBadRequest)
	}
}

// TestInTxKeepsTheRollbackPrivate covers what the client reads after a
// rollback. The handler already wrote the answer, so the marker that ended the
// transaction must not replace it.
func TestInTxKeepsTheRollbackPrivate(t *testing.T) {
	runner := &recordingRunner{}
	app := txApp(t, runner, func(c fiber.Ctx) error {
		return c.Status(fiber.StatusBadRequest).SendString(`{"error":"invalid_grant"}`)
	})

	answer, err := app.Test(httptest.NewRequest(fiber.MethodGet, "/x", nil))
	if err != nil {
		t.Fatalf("test request: %v", err)
	}
	defer answer.Body.Close()

	body := make([]byte, 64)
	n, _ := answer.Body.Read(body)
	if got := string(body[:n]); got != `{"error":"invalid_grant"}` {
		t.Errorf("the client read %q, want the answer the handler wrote", got)
	}
}

// TestInTxRollsBackOnAHandlerError covers a handler that returns rather than
// answers. The error ends the transaction and still reaches Fiber, which maps
// it to the envelope.
func TestInTxRollsBackOnAHandlerError(t *testing.T) {
	broken := errors.New("the store is unreachable")
	runner := &recordingRunner{}
	app := txApp(t, runner, func(fiber.Ctx) error { return broken })

	answer, err := app.Test(httptest.NewRequest(fiber.MethodGet, "/x", nil))
	if err != nil {
		t.Fatalf("test request: %v", err)
	}
	defer answer.Body.Close()

	if !runner.rollback {
		t.Error("a handler error did not roll the transaction back")
	}
	if answer.StatusCode != fiber.StatusInternalServerError {
		t.Errorf("the status is %d, want %d", answer.StatusCode, fiber.StatusInternalServerError)
	}
}
