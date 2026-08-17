package middlewares

import (
	"encoding/json"
	"io"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gofiber/fiber/v3"

	"alphaomega/identitygateway/internal/api/http/response"
)

// pagedApp mounts the pagination middleware in front of one list handler. The
// handler answers the rows the test gives it, so the assertions read the page
// state the middleware resolved and the meta the response helper wrote.
func pagedApp(rows []string, total int64) *fiber.App {
	app := fiber.New()
	app.Get("/x", Paginate("created_at", "name"), func(c fiber.Ctx) error {
		return response.List(c, rows, total)
	})
	return app
}

// answerOf runs one request and reads the envelope back.
func answerOf(t *testing.T, app *fiber.App, target string) (int, map[string]any) {
	t.Helper()

	answer, err := app.Test(httptest.NewRequest(fiber.MethodGet, target, nil))
	if err != nil {
		t.Fatalf("test request: %v", err)
	}
	defer answer.Body.Close()

	body, err := io.ReadAll(answer.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}

	var envelope map[string]any
	if err := json.Unmarshal(body, &envelope); err != nil {
		t.Fatalf("decode %q: %v", body, err)
	}
	return answer.StatusCode, envelope
}

// TestPaginateRefusesASortKeyOutsideTheAllowlist covers the sort an operator
// cannot have. The list builds its ORDER BY from the allowlist only, so a key
// outside it is refused rather than dropped: a silently ignored sort answers a
// different question from the one the operator asked.
func TestPaginateRefusesASortKeyOutsideTheAllowlist(t *testing.T) {
	status, envelope := answerOf(t, pagedApp(nil, 0), "/x?sort=password_hash")

	if status != fiber.StatusUnprocessableEntity {
		t.Fatalf("the status is %d, want %d", status, fiber.StatusUnprocessableEntity)
	}
	if got := envelope["error"]; got != "invalid_input" {
		t.Errorf("the slug is %v, want invalid_input", got)
	}

	message, _ := envelope["message"].(string)
	for _, want := range []string{"password_hash", "created_at", "name"} {
		if !strings.Contains(message, want) {
			t.Errorf("the message %q does not name %q", message, want)
		}
	}
}

// TestPaginateAdmitsAnAllowedSortKey covers the other half of the same rule. A
// descending key carries a leading "-", and the name after it is what the
// allowlist is read against.
func TestPaginateAdmitsAnAllowedSortKey(t *testing.T) {
	status, _ := answerOf(t, pagedApp([]string{"a"}, 1), "/x?sort=-created_at")

	if status != fiber.StatusOK {
		t.Fatalf("the status is %d, want %d", status, fiber.StatusOK)
	}
}

// TestPaginateClampsALimitAboveTheMaximum covers the oversized page. The limit
// is clamped, not refused, so a client that asks for too much still reads an
// answer, and the meta states the size it actually got.
func TestPaginateClampsALimitAboveTheMaximum(t *testing.T) {
	status, envelope := answerOf(t, pagedApp([]string{"a"}, 1), "/x?limit=5000")

	if status != fiber.StatusOK {
		t.Fatalf("the status is %d, want %d", status, fiber.StatusOK)
	}

	meta, _ := envelope["meta"].(map[string]any)
	if got := meta["limit"]; got != float64(maxPageLimit) {
		t.Errorf("the limit is %v, want %d", got, maxPageLimit)
	}
}

// TestPaginateAnswersAPagePastTheEnd covers the page an operator reaches after
// rows were removed. The list is empty and the total still counts the whole
// collection, so the pager can send the operator back to a page that holds rows.
func TestPaginateAnswersAPagePastTheEnd(t *testing.T) {
	status, envelope := answerOf(t, pagedApp([]string{}, 42), "/x?page=99&limit=10")

	if status != fiber.StatusOK {
		t.Fatalf("the status is %d, want %d", status, fiber.StatusOK)
	}

	rows, _ := envelope["data"].([]any)
	if len(rows) != 0 {
		t.Errorf("the list holds %d rows, want none", len(rows))
	}

	meta, _ := envelope["meta"].(map[string]any)
	if got := meta["total"]; got != float64(42) {
		t.Errorf("the total is %v, want 42", got)
	}
	if got := meta["page"]; got != float64(99) {
		t.Errorf("the page is %v, want 99", got)
	}
	if got := meta["totalPages"]; got != float64(5) {
		t.Errorf("the total pages is %v, want 5", got)
	}
}
