package audit

import (
	"time"

	"github.com/uptrace/bun"
)

// Event is one row of audit_events. The table is append-only: a row is never
// updated and never deleted, so the model carries no soft-delete column.
//
// Metadata holds non-secret context only. The recorder decides what reaches it.
type Event struct {
	bun.BaseModel `bun:"table:audit_events"`

	ID         string `bun:"id,pk"`
	TenantID   string `bun:"tenant_id"`
	ActorID    string `bun:"actor_id,nullzero"`
	Action     string `bun:"action"`
	EntityType string `bun:"entity_type"`
	EntityID   string `bun:"entity_id,nullzero"`
	Result     string `bun:"result"`
	IP         string `bun:"ip,nullzero"`
	UserAgent  string `bun:"user_agent,nullzero"`
	// Metadata is bound as a string, not as bytes. The column is MySQL JSON,
	// and the driver sends a []byte as a binary string, which MySQL refuses to
	// read as JSON.
	Metadata  string    `bun:"metadata,nullzero"`
	CreatedAt time.Time `bun:"created_at"`
}
