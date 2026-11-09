package eet

import (
	"encoding/json"
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

func TestSaleReversal(t *testing.T) {
	t.Parallel()
	at := time.Date(2027, 9, 10, 17, 8, 33, 0, Prague)
	for _, tc := range []struct {
		name string
		sale Sale
		want Sale
	}{
		{
			name: "plain sale",
			sale: Sale{EIC: testEIC, UnitID: 121, RegisterID: "fra26", SequenceNumber: "12678", Time: at.AddDate(0, 0, -7), Total: Crowns(5450)},
			want: Sale{EIC: testEIC, UnitID: 121, RegisterID: "fra26", SequenceNumber: "12829", Time: at, Total: Crowns(-5450)},
		},
		{
			name: "drawdown from a prepaid card",
			sale: Sale{EIC: testEIC, UnitID: 81, RegisterID: "MC001", SequenceNumber: "45-aja-67", Time: at.Add(-time.Hour), Total: Crowns(121), Drawdown: new(Crowns(121))},
			want: Sale{EIC: testEIC, UnitID: 81, RegisterID: "MC001", SequenceNumber: "12829", Time: at, Total: Crowns(-121), Drawdown: new(Crowns(-121))},
		},
		{
			name: "top-up",
			sale: Sale{EIC: testEIC, UnitID: 1551, RegisterID: "0001", SequenceNumber: "3210", Time: at.Add(-time.Hour), Total: Crowns(1050), TopUp: new(Crowns(1000))},
			want: Sale{EIC: testEIC, UnitID: 1551, RegisterID: "0001", SequenceNumber: "12829", Time: at, Total: Crowns(-1050), TopUp: new(Crowns(-1000))},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			original := tc.sale.Key()
			got := tc.sale.Reversal(Reversal{Time: at, SequenceNumber: "12829"})
			if got.Key() != tc.want.Key() || !equalAmount(got.TopUp, tc.want.TopUp) || !equalAmount(got.Drawdown, tc.want.Drawdown) {
				t.Fatalf("Reversal() = %+v, want %+v", got, tc.want)
			}
			if tc.sale.Key() != original || (tc.sale.Drawdown != nil && *tc.sale.Drawdown < 0) {
				t.Fatal("Reversal must not modify the original sale")
			}
		})
	}
}

func equalAmount(a, b *Amount) bool {
	return (a == nil && b == nil) || (a != nil && b != nil && *a == *b)
}

func TestSaleResendDeadline(t *testing.T) {
	t.Parallel()
	s := Sale{Time: time.Date(2027, 4, 25, 15, 30, 40, 0, Prague)}
	if got, want := s.ResendDeadline(), time.Date(2027, 4, 27, 15, 30, 40, 0, Prague); !got.Equal(want) {
		t.Fatalf("ResendDeadline() = %v, want %v", got, want)
	}
}

func TestSaleJSON(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name    string
		input   string
		want    Sale
		wantErr bool
	}{
		{
			name:  "all fields",
			input: `{"eic":"CZ8551015704","delegatingEic":"CZ00000019","multipleTaxpayers":true,"unitId":181,"registerId":"00/2535/CN58","sequenceNumber":"0/2482/IE25","time":"2027-01-07T22:01:00+01:00","total":"87988.00","topUp":"343.00","drawdown":"237.00"}`,
			want:  specSale(),
		},
		{
			name:  "negative total without optional fields",
			input: `{"eic":"CZ00000019","unitId":51,"registerId":"04","sequenceNumber":"7139935","time":"2027-09-04T08:12:46+02:00","total":"-24.00"}`,
			want:  Sale{EIC: "CZ00000019", UnitID: 51, RegisterID: "04", SequenceNumber: "7139935", Time: time.Date(2027, 9, 4, 8, 12, 46, 0, Prague), Total: Crowns(-24)},
		},
		{name: "non-canonical amount", input: `{"total":"020.45"}`, wantErr: true},
		{name: "number instead of string", input: `{"total":20.45}`, wantErr: true},
		{name: "whole number would be read as halers", input: `{"total":20}`, wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var got Sale
			err := json.Unmarshal([]byte(tc.input), &got)
			if (err != nil) != tc.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tc.wantErr)
			}
			if tc.wantErr {
				return
			}
			if got.Key() != tc.want.Key() || got.DelegatingEIC != tc.want.DelegatingEIC || got.MultipleTaxpayers != tc.want.MultipleTaxpayers || !equalAmount(got.TopUp, tc.want.TopUp) || !equalAmount(got.Drawdown, tc.want.Drawdown) {
				t.Fatalf("got %+v, want %+v", got, tc.want)
			}
			out, err := json.Marshal(got)
			if err != nil {
				t.Fatal(err)
			}
			var back Sale
			if err := json.Unmarshal(out, &back); err != nil || back.Key() != got.Key() {
				t.Fatalf("round trip %s: %v", out, err)
			}
		})
	}
}
