package eet

import (
	"testing"
	"time"
)

func TestEnvironmentMinSaleTimeAt(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name string
		env  Environment
		now  time.Time
		want time.Time
	}{
		{name: "playground", env: Playground, now: time.Date(2026, 11, 9, 12, 0, 0, 0, Prague), want: time.Date(2026, 7, 1, 0, 0, 0, 0, Prague)},
		{name: "production before go-live accepts transitional sales", env: Production, now: time.Date(2026, 12, 31, 23, 59, 59, 0, Prague), want: time.Date(2026, 11, 1, 0, 0, 0, 0, Prague)},
		{name: "production after go-live", env: Production, now: time.Date(2027, 1, 1, 0, 0, 0, 0, Prague), want: time.Date(2027, 1, 1, 0, 0, 0, 0, Prague)},
		{name: "custom environment has no minimum", env: Environment{URL: "https://example.test"}, now: time.Now()},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := tc.env.MinSaleTimeAt(tc.now); !got.Equal(tc.want) {
				t.Fatalf("MinSaleTimeAt() = %v, want %v", got, tc.want)
			}
		})
	}
}
