package db

import (
	"context"
	"database/sql"

	"github.com/uptrace/bun"
)

type txKey struct{}

func txFromContext(ctx context.Context) (bun.Tx, bool) {
	tx, ok := ctx.Value(txKey{}).(bun.Tx)
	return tx, ok
}

// TxFrom returns the transaction the context carries, if it carries one.
//
// A caller needs this only to move the transaction onto a second carrier. The
// OIDC stack is the one such caller: the Fiber adaptor hands the protocol
// engine a request context of its own, and that context reaches the engine's
// stores instead of this one.
func TxFrom(ctx context.Context) (bun.Tx, bool) {
	return txFromContext(ctx)
}

// TxKey is the key a transaction travels under. A carrier that is not a
// context.Context, such as a fasthttp request context, must store the
// transaction under this key for Conn to find it again.
func TxKey() any {
	return txKey{}
}

// TxRunner runs one unit of work on a transaction. It is what
// TxManager.RunInTx is, named once, so a caller takes the behaviour without
// declaring the signature again.
type TxRunner func(ctx context.Context, fn func(ctx context.Context) error) error

// TxManager satisfies the Tx interfaces declared by services. Usage:
//
//	err := tx.RunInTx(ctx, func(ctx context.Context) error {
//	    if err := users.Create(ctx, u); err != nil { return err }
//	    return audit.Write(ctx, entry) // same tx via ctx
//	})
type TxManager struct{ db *bun.DB }

func NewTxManager(bdb *bun.DB) *TxManager { return &TxManager{db: bdb} }

func (m *TxManager) RunInTx(ctx context.Context, fn func(ctx context.Context) error) error {
	if _, ok := txFromContext(ctx); ok {
		return fn(ctx) // already in a tx: join it, don't nest
	}
	return m.db.RunInTx(ctx, &sql.TxOptions{}, func(ctx context.Context, tx bun.Tx) error {
		return fn(context.WithValue(ctx, txKey{}, tx))
	})
}
