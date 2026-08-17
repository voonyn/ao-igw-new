package middlewares

import (
	"context"
	"errors"

	"github.com/gofiber/fiber/v3"

	"alphaomega/identitygateway/internal/platform/db"
	"alphaomega/identitygateway/internal/platform/logger"
)

// errRollback ends the transaction of a request the handler already answered
// with an error. It never reaches the client, because the answer is written by
// then.
var errRollback = errors.New("roll the request back")

// InTx runs one request inside a database transaction, so every write of that
// request lands together or not at all.
//
// The token endpoint needs this. The protocol engine records token.issued and
// saves the grant as two writes, and the slice rule holds that an audit write
// runs in the same transaction as the change it records.
//
// The transaction is put on two carriers. Fiber hands it to a Go handler
// through the request context, and the adaptor hands the protocol engine a
// fasthttp request context instead, which reads user values. Both carriers
// answer db.Conn, so a repository finds the transaction either way.
//
// A response of 400 or worse rolls the transaction back. The handler has
// already written that answer, so the rollback is silent to the client.
func InTx(run db.TxRunner, log logger.Logger) fiber.Handler {
	return func(c fiber.Ctx) error {
		err := run(c.Context(), func(ctx context.Context) error {
			c.SetContext(ctx)
			tx, ok := db.TxFrom(ctx)
			if !ok {
				// The protocol engine reads the second carrier only. Without
				// this hop its writes leave the transaction, and nothing later
				// in the request reveals that, so say it here.
				log.Error("no transaction to carry to the request context",
					logger.String("path", c.Path()))
			} else {
				c.RequestCtx().SetUserValue(db.TxKey(), tx)
			}

			if err := c.Next(); err != nil {
				return err
			}
			if c.Response().StatusCode() >= fiber.StatusBadRequest {
				return errRollback
			}
			return nil
		})

		if errors.Is(err, errRollback) {
			return nil
		}
		if err != nil {
			log.Error("run request in a transaction",
				logger.String("path", c.Path()),
				logger.Err(err))
		}
		return err
	}
}
