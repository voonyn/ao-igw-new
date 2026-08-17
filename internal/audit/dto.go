package audit

import (
	"encoding/json"
	"time"
)

// Query is the window and the narrowing of one read of the feed.
//
// The five filters are conjoined: a read that names an actor and an action
// answers the events that person took of that action. The console cannot ask
// for the union of two of them, so "what this person did" and "what was done to
// this person" are two reads.
//
// From and To bound created_at. From is inclusive and To is exclusive, so two
// adjacent ranges neither drop an event nor report one twice.
type Query struct {
	Actor      string
	Action     string
	EntityType string
	EntityID   string
	From       time.Time
	To         time.Time

	Sort   string
	Desc   bool
	Limit  int
	Offset int
}

// EventView is one audit event as the console reads it.
//
// Actor is empty when the gateway itself took the action, and the console then
// renders "System" or, on a failure, "Unknown".
//
// Metadata is the JSON the column holds, forwarded as it is. The recorder
// already dropped every key outside its allow-list, so no credential is in it. A
// row that holds none carries no field at all, because an empty string is not
// JSON and the console parses this value.
type EventView struct {
	ID         string          `json:"id"`
	Actor      string          `json:"actor,omitempty"`
	Action     string          `json:"action"`
	EntityType string          `json:"entityType"`
	EntityID   string          `json:"entityId,omitempty"`
	Result     string          `json:"result"`
	IP         string          `json:"ip,omitempty"`
	UserAgent  string          `json:"userAgent,omitempty"`
	Metadata   json.RawMessage `json:"metadata,omitempty"`
	CreatedAt  time.Time       `json:"createdAt"`
}
