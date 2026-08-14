package db

import (
	"errors"

	"github.com/go-sql-driver/mysql"
)

// IsUniqueViolation translates MySQL error 1062 (ER_DUP_ENTRY) so upper
// layers see a domain error, never a driver error.
func IsUniqueViolation(err error) bool {
	var mysqlErr *mysql.MySQLError
	return errors.As(err, &mysqlErr) && mysqlErr.Number == 1062
}
