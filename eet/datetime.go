package eet

import (
	"errors"
	"fmt"
	"strings"
	"time"
	_ "time/tzdata"
)

const (
	dateTimeLayout     = "2006-01-02T15:04:05Z07:00"
	minRepresentedYear = 1
	maxRepresentedYear = 9999
	secondsPerMinute   = 60
)

var Prague = mustLoadLocation("Europe/Prague")

func mustLoadLocation(name string) *time.Location {
	loc, err := time.LoadLocation(name)
	if err != nil {
		panic(err)
	}
	return loc
}

func FormatDateTime(t time.Time) string {
	return t.Format(dateTimeLayout)
}

func validDateTime(t time.Time) error {
	if t.IsZero() {
		return errors.New("time is not set")
	}
	if y := t.Year(); y < minRepresentedYear || y > maxRepresentedYear {
		return fmt.Errorf("year %d cannot be represented as yyyy", y)
	}
	if _, off := t.Zone(); off%secondsPerMinute != 0 {
		return fmt.Errorf("zone offset %ds cannot be represented as ±hh:mm", off)
	}
	return nil
}

func parseOptionalDateTime(s string) (time.Time, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}, nil
	}
	return time.Parse(time.RFC3339, s)
}
