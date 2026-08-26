package audit

import "time"

// ActivityView is one audit event as the person it belongs to reads it.
//
// It is EventView without the two operator-facing fields. Actor is dropped
// because every row of this feed names the caller, so the field carries no
// information and repeating the account id on every row discloses it to nobody
// who needed it. Metadata is dropped because it is context an operator reads
// while investigating, and the portal renders none of it.
//
// Both fields are absent from the answer, not present and empty. A client that
// finds no key cannot start rendering one.
type ActivityView struct {
	ID         string    `json:"id"`
	Action     string    `json:"action"`
	EntityType string    `json:"entityType"`
	EntityID   string    `json:"entityId,omitempty"`
	Result     string    `json:"result"`
	IP         string    `json:"ip,omitempty"`
	UserAgent  string    `json:"userAgent,omitempty"`
	CreatedAt  time.Time `json:"createdAt"`
}
