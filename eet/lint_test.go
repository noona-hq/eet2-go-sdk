package eet

import (
	"slices"
	"testing"
	"time"
)

func TestSaleLint(t *testing.T) {
	t.Parallel()
	now := time.Date(2027, 3, 1, 12, 0, 0, 0, Prague)
	cert := playgroundSigner(t, testEIC).Certificate()
	base := Sale{EIC: testEIC, UnitID: 24, RegisterID: "1", SequenceNumber: "1", Time: now, Total: Halers(100)}
	for _, tc := range []struct {
		name   string
		mutate func(Sale) Sale
		opts   LintOptions
		want   []WarningCode
	}{
		{name: "clean", mutate: func(s Sale) Sale { return s }, opts: LintOptions{Certificate: cert, Now: now, MinSaleTime: Production.MinSaleTime}},
		{name: "1 EIC differs from certificate", mutate: func(s Sale) Sale { s.EIC = "CZ683555118"; return s }, opts: LintOptions{Certificate: cert, Now: now}, want: []WarningCode{WarningEICMismatch}},
		{name: "2 delegating EIC format", mutate: func(s Sale) Sale { s.DelegatingEIC = "CZ1"; return s }, opts: LintOptions{Now: now}, want: []WarningCode{WarningDelegatingEICFormat}},
		{name: "4 sale more than two hours ahead", mutate: func(s Sale) Sale { s.Time = now.Add(2*time.Hour + time.Second); return s }, opts: LintOptions{Now: now}, want: []WarningCode{WarningSaleTimeInFuture}},
		{name: "4 two hours ahead is allowed", mutate: func(s Sale) Sale { s.Time = now.Add(2 * time.Hour); return s }, opts: LintOptions{Now: now}},
		{name: "5 older than two years", mutate: func(s Sale) Sale { s.Time = now.AddDate(-2, 0, -1); return s }, opts: LintOptions{Now: now}, want: []WarningCode{WarningSaleTimeTooOld}},
		{name: "5 before environment minimum", mutate: func(s Sale) Sale { s.Time = Production.MinSaleTime.Add(-time.Second); return s }, opts: LintOptions{Now: now, MinSaleTime: Production.MinSaleTime}, want: []WarningCode{WarningSaleTimeTooOld}},
		{name: "6 single digit unit", mutate: func(s Sale) Sale { s.UnitID = 4; return s }, opts: LintOptions{Now: now}, want: []WarningCode{WarningUnitIDFormat}},
		{name: "6 unit ending with 5", mutate: func(s Sale) Sale { s.UnitID = 25; return s }, opts: LintOptions{Now: now}, want: []WarningCode{WarningUnitIDFormat}},
		{name: "7 delegating EIC equals own EIC", mutate: func(s Sale) Sale { s.DelegatingEIC = s.EIC; return s }, opts: LintOptions{Now: now}, want: []WarningCode{WarningDelegatingEICIsOwner}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var got []WarningCode
			for _, w := range tc.mutate(base).Lint(tc.opts) {
				if w.Message == "" {
					t.Errorf("warning %d has no message", w.Code)
				}
				got = append(got, w.Code)
			}
			if !slices.Equal(got, tc.want) {
				t.Fatalf("warnings = %v, want %v", got, tc.want)
			}
		})
	}
}
