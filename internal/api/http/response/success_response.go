package response

import (
	"github.com/gofiber/fiber/v3"
	"github.com/gofiber/fiber/v3/middleware/paginate"
)

// OK writes 200 with the standard envelope.
func OK(c fiber.Ctx, data any) error {
	return write(c, fiber.StatusOK, "OK", data, nil)
}

// Created writes 201 with the standard envelope.
func Created(c fiber.Ctx, data any) error {
	return write(c, fiber.StatusCreated, "Created", data, nil)
}

// NoContent writes 200 with a null data field, for a mutation that returns
// nothing. It is not 204, so the client always parses the same envelope.
func NoContent(c fiber.Ctx) error {
	return write(c, fiber.StatusOK, "OK", nil, nil)
}

// List writes 200 with the standard envelope plus pagination meta. It reads the
// page and limit from the paginate middleware, so the route must mount it.
// total is the row count before the limit is applied.
//
// ponytail: offset pagination only. Cursor mode leaves PageInfo.Page at zero and
// needs a nextCursor field in Meta. Add it when a list grows past the point where
// OFFSET hurts.
func List(c fiber.Ctx, data any, total int64) error {
	page, limit := 1, 0
	if info, ok := paginate.FromContext(c); ok && info != nil {
		page, limit = info.Page, info.Limit
	}
	if page < 1 {
		page = 1
	}
	if limit < 1 {
		limit = 1
	}

	meta := &Meta{
		Page:       page,
		Limit:      limit,
		Total:      total,
		TotalPages: (total + int64(limit) - 1) / int64(limit),
	}

	return write(c, fiber.StatusOK, "OK", data, meta)
}

func write(c fiber.Ctx, statusCode int, message string, data any, meta *Meta) error {
	return c.Status(statusCode).JSON(Success{
		Code:    statusCode,
		Status:  "success",
		Message: message,
		Data:    data,
		Meta:    meta,
	})
}
