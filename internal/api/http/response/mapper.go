package response

import (
	"errors"

	"github.com/gofiber/fiber/v3"
)

// rule turns one domain sentinel into what the client reads.
type rule struct {
	err     error
	status  int
	slug    string
	message string
}

// rules is the whole mapping table. Every domain imports this package, so this
// package can import none of them: a domain registers its own sentinels
// instead, from an init function in its handler file.
//
// The table is written at init and read from there on, so it needs no lock.
var rules []rule

// Map registers one sentinel with the status, the slug, and the message it
// answers. Call it from an init function only. The first rule that matches
// wins, so register the narrow sentinel before the broad one.
//
// Two sentinels can share one slug. A client must not tell them apart when the
// answer is deliberately alike, such as an unknown identifier and a wrong
// password.
func Map(err error, status int, slug, message string) {
	rules = append(rules, rule{err: err, status: status, slug: slug, message: message})
}

// Fail writes the envelope one domain error maps to. A handler passes its error
// here and maps nothing itself.
//
// An unregistered error comes back unchanged. The handler returns it, and
// ErrorHandler then answers 500 without disclosing the wrapped text.
func Fail(c fiber.Ctx, err error) error {
	for _, r := range rules {
		if errors.Is(err, r.err) {
			return ErrorSlug(c, r.status, r.slug, r.message)
		}
	}
	return err
}
