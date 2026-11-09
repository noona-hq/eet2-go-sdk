package eet

import (
	"errors"
	"strings"
	"testing"
	"time"
)

func specSale() Sale {
	return Sale{
		EIC:               "CZ8551015704",
		DelegatingEIC:     "CZ00000019",
		MultipleTaxpayers: true,
		UnitID:            181,
		RegisterID:        "00/2535/CN58",
		SequenceNumber:    "0/2482/IE25",
		Time:              time.Date(2027, 1, 7, 22, 1, 0, 0, Prague),
		Total:             Halers(8798800),
		TopUp:             new(Halers(34300)),
		Drawdown:          new(Halers(23700)),
	}
}

func TestSaleValidate(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name       string
		mutate     func(Sale) Sale
		wantField  string
		wantReason string
	}{
		{name: "spec example", mutate: func(s Sale) Sale { return s }},
		{name: "spec id_pokl and porad_cis examples", mutate: func(s Sale) Sale {
			s.RegisterID, s.SequenceNumber = "5a/A-q/5:22d_2", "#25/c-12/1A_2/2027"
			return s
		}},
		{name: "longest identifiers", mutate: func(s Sale) Sale {
			s.EIC, s.UnitID, s.RegisterID, s.SequenceNumber = "CZ8551015704", MaxUnitID, strings.Repeat("A", 20), strings.Repeat("1", 25)
			return s
		}},
		{name: "eic_popl without country code", mutate: func(s Sale) Sale { s.EIC = "00000019"; return s }, wantField: "eic_popl", wantReason: "does not match"},
		{name: "eic_popl too short", mutate: func(s Sale) Sale { s.EIC = "CZ1234567"; return s }, wantField: "eic_popl", wantReason: "does not match"},
		{name: "eic_popl too long", mutate: func(s Sale) Sale { s.EIC = "CZ12345678901"; return s }, wantField: "eic_popl", wantReason: "does not match"},
		{name: "eic_poverujiciho invalid", mutate: func(s Sale) Sale { s.DelegatingEIC = "SK00000019"; return s }, wantField: "eic_poverujiciho", wantReason: "does not match"},
		{name: "id_jednotky zero", mutate: func(s Sale) Sale { s.UnitID = 0; return s }, wantField: "id_jednotky", wantReason: "outside 1..999999999"},
		{name: "id_jednotky too large", mutate: func(s Sale) Sale { s.UnitID = MaxUnitID + 1; return s }, wantField: "id_jednotky", wantReason: "outside 1..999999999"},
		{name: "id_pokl empty", mutate: func(s Sale) Sale { s.RegisterID = ""; return s }, wantField: "id_pokl", wantReason: "does not match"},
		{name: "id_pokl too long", mutate: func(s Sale) Sale { s.RegisterID = strings.Repeat("A", 21); return s }, wantField: "id_pokl", wantReason: "does not match"},
		{name: "id_pokl diacritics", mutate: func(s Sale) Sale { s.RegisterID = "Pokladna č. 1"; return s }, wantField: "id_pokl", wantReason: "does not match"},
		{name: "porad_cis empty", mutate: func(s Sale) Sale { s.SequenceNumber = ""; return s }, wantField: "porad_cis", wantReason: "does not match"},
		{name: "porad_cis too long", mutate: func(s Sale) Sale { s.SequenceNumber = strings.Repeat("1", 26); return s }, wantField: "porad_cis", wantReason: "does not match"},
		{name: "porad_cis forbidden character", mutate: func(s Sale) Sale { s.SequenceNumber = "a&b"; return s }, wantField: "porad_cis", wantReason: "does not match"},
		{name: "dat_trzby missing", mutate: func(s Sale) Sale { s.Time = time.Time{}; return s }, wantField: "dat_trzby", wantReason: "time is not set"},
		{name: "dat_trzby year beyond 9999", mutate: func(s Sale) Sale { s.Time = time.Date(10000, 1, 1, 0, 0, 0, 0, Prague); return s }, wantField: "dat_trzby", wantReason: "cannot be represented as yyyy"},
		{name: "dat_trzby offset with seconds", mutate: func(s Sale) Sale {
			s.Time = time.Date(2027, 1, 1, 0, 0, 0, 0, time.FixedZone("LMT", 3464))
			return s
		}, wantField: "dat_trzby", wantReason: "cannot be represented as ±hh:mm"},
		{name: "celk_trzba out of range", mutate: func(s Sale) Sale { s.Total = Halers(10000000000); return s }, wantField: "celk_trzba", wantReason: ErrAmountOutOfRange.Error()},
		{name: "urceno_cerp_zuct out of range", mutate: func(s Sale) Sale { s.TopUp = new(Halers(-10000000000)); return s }, wantField: "urceno_cerp_zuct", wantReason: ErrAmountOutOfRange.Error()},
		{name: "cerp_zuct out of range", mutate: func(s Sale) Sale { s.Drawdown = new(Halers(10000000000)); return s }, wantField: "cerp_zuct", wantReason: ErrAmountOutOfRange.Error()},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := tc.mutate(specSale()).Validate()
			if tc.wantField == "" {
				if err != nil {
					t.Fatalf("unexpected error %v", err)
				}
				return
			}
			ve, ok := errors.AsType[*ValidationError](err)
			if !ok || ve.Field != tc.wantField || !strings.Contains(ve.Reason, tc.wantReason) {
				t.Fatalf("err = %v, want %s containing %q", err, tc.wantField, tc.wantReason)
			}
		})
	}
}

func TestSaleValidateReportsEveryViolation(t *testing.T) {
	t.Parallel()
	err := Sale{}.Validate()
	ves, ok := errors.AsType[ValidationErrors](err)
	if !ok {
		t.Fatalf("err = %T, want ValidationErrors", err)
	}
	var fields []string
	for _, ve := range ves {
		fields = append(fields, ve.Field)
	}
	if got, want := strings.Join(fields, ","), "eic_popl,id_jednotky,id_pokl,porad_cis,dat_trzby"; got != want {
		t.Fatalf("fields = %s, want %s", got, want)
	}
}

func TestSaleKey(t *testing.T) {
	t.Parallel()
	s := Sale{
		EIC:            "CZ00000019",
		UnitID:         243,
		RegisterID:     "24/A-6/Brno_2",
		SequenceNumber: "#135433c/11/2027",
		Time:           time.Date(2027, 1, 9, 16, 45, 36, 0, Prague),
		Total:          Halers(326450),
	}
	want := "CZ00000019|243|24/A-6/Brno_2|#135433c/11/2027|2027-01-09T16:45:36+01:00|3264.50"
	if got := s.Key(); got != want {
		t.Fatalf("Key() = %q, want %q", got, want)
	}
}
