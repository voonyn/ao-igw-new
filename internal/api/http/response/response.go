// Package response holds the transport's wire shapes: the success envelope and
// the error envelope the gateway emits.
//
// It is the old repo's internal/response, moved under internal/api/http per the
// migration's package mapping. It sits in its own package (rather than in
// internal/api/http itself) because both the handler and middleware packages
// write these shapes while internal/api/http imports both — a shared leaf is the
// only home that keeps the import graph acyclic. It imports nothing from
// internal/* and never logs: the caller holds the structured logger.
package response

// Failure is the error envelope. Every error answer reads
// {code, status, message, error, errors?}.
//
// Error is a machine-readable slug, and a client branches on it, never on
// Message, so a reworded message never changes behaviour. Errors is present
// only when the answer names the fields that failed.
type Failure struct {
	Code    int    `json:"code"`
	Status  string `json:"status"`
	Message string `json:"message"`
	Error   string `json:"error"`
	Errors  any    `json:"errors,omitempty"`
}

// Success is the envelope for every non-error response. Meta is present only on
// list responses.
type Success struct {
	Code    int    `json:"code"`
	Status  string `json:"status"`
	Message string `json:"message"`
	Data    any    `json:"data"`
	Meta    *Meta  `json:"meta,omitempty"`
}

// Meta carries the pagination state of a list response.
type Meta struct {
	Page       int   `json:"page"`
	Limit      int   `json:"limit"`
	Total      int64 `json:"total"`
	TotalPages int64 `json:"totalPages"`
}
