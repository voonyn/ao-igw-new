package db

import (
	"errors"
	"fmt"
	"testing"

	"github.com/go-sql-driver/mysql"
)

func TestIsUniqueViolation(t *testing.T) {
	dup := &mysql.MySQLError{Number: 1062, Message: "duplicate entry"}
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, false},
		{"duplicate key", dup, true},
		{"wrapped duplicate key", fmt.Errorf("insert: %w", dup), true}, // errors.As must unwrap %w
		{"other mysql error", &mysql.MySQLError{Number: 1146}, false},  // ER_NO_SUCH_TABLE
		{"non-driver error", errors.New("boom"), false},
	}
	for _, tt := range tests {
		if got := IsUniqueViolation(tt.err); got != tt.want {
			t.Errorf("%s: IsUniqueViolation = %v, want %v", tt.name, got, tt.want)
		}
	}
}
