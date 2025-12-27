package stores

import (
	"time"

	"github.com/oarkflow/date"
)

func parseFlexibleTime(s string) (time.Time, error) {
	return date.Parse(s)
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

func sqlNullTimeOrNil(t time.Time) interface{} {
	if t.IsZero() {
		return nil
	}
	return t
}
