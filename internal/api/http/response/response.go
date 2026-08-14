// Package response holds the transport's wire shapes: the two JSON error
// envelopes the gateway emits and the health-probe payload.
//
// It is the old repo's internal/response, moved under internal/api/http per the
// migration's package mapping. It sits in its own package (rather than in
// internal/api/http itself) because both the handler and middleware packages
// write these shapes while internal/api/http imports both — a shared leaf is the
// only home that keeps the import graph acyclic. It imports nothing from
// internal/* and never logs: the caller holds the structured logger.
package response

type Common struct {
	Code    int    `json:"code"`
	Status  string `json:"status"`
	Message string `json:"message"`
}

type ErrorDetails struct {
	Code    int    `json:"code"`
	Status  string `json:"status"`
	Message string `json:"message"`
	Errors  any    `json:"errors"`
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
