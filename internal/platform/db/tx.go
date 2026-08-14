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
