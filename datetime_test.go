package eet

import (
	"testing"
	"time"
)

func TestFormatDateTime(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name  string
		input time.Time
		want  string
	}{
		{name: "spec winter time", input: time.Date(2027, 1, 9, 3, 25, 28, 0, time.UTC).In(Prague), want: "2027-01-09T04:25:28+01:00"},
		{name: "spec summer time", input: time.Date(2027, 6, 9, 3, 25, 28, 0, time.UTC).In(Prague), want: "2027-06-09T05:25:28+02:00"},
		{name: "UTC as Z without fraction", input: time.Date(2026, 7, 1, 9, 2, 18, 999, time.UTC), want: "2026-07-01T09:02:18Z"},
		{name: "negative offset", input: time.Date(2027, 1, 1, 0, 0, 0, 0, time.FixedZone("", -5*3600)), want: "2027-01-01T00:00:00-05:00"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := FormatDateTime(tc.input); got != tc.want {
				t.Fatalf("FormatDateTime() = %q, want %q", got, tc.want)
			}
		})
	}
}
