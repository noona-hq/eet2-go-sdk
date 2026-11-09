package eet

import (
	"errors"
	"testing"
)

func TestAmountString(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name   string
		amount Amount
		want   string
	}{
		{name: "spec 20.45", amount: Halers(2045), want: "20.45"},
		{name: "spec 10.25", amount: Halers(1025), want: "10.25"},
		{name: "zero has no sign", amount: Halers(0), want: "0.00"},
		{name: "leading zero before point", amount: Halers(20), want: "0.20"},
		{name: "negative whole", amount: Halers(-10000), want: "-100.00"},
		{name: "smallest negative", amount: Halers(-1), want: "-0.01"},
		{name: "spec -187.20", amount: Halers(-18720), want: "-187.20"},
		{name: "crowns", amount: Crowns(250), want: "250.00"},
		{name: "maximum", amount: Halers(9999999999), want: "99999999.99"},
		{name: "minimum", amount: Halers(-9999999999), want: "-99999999.99"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := tc.amount.String()
			if got != tc.want {
				t.Fatalf("String() = %q, want %q", got, tc.want)
			}
			if !amountPattern.MatchString(got) {
				t.Fatalf("%q does not match the XSD pattern", got)
			}
		})
	}
}

func TestParseAmount(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name    string
		input   string
		want    Amount
		wantErr bool
	}{
		{name: "spec 250.00", input: "250.00", want: Halers(25000)},
		{name: "spec -187.20", input: "-187.20", want: Halers(-18720)},
		{name: "spec 0.56", input: "0.56", want: Halers(56)},
		{name: "smallest negative", input: "-0.01", want: Halers(-1)},
		{name: "maximum", input: "99999999.99", want: Halers(9999999999)},
		{name: "spec wrong 020.45", input: "020.45", wantErr: true},
		{name: "spec wrong 00010.25", input: "00010.25", wantErr: true},
		{name: "spec wrong -0.00", input: "-0.00", wantErr: true},
		{name: "spec wrong -00.00", input: "-00.00", wantErr: true},
		{name: "spec wrong .20", input: ".20", wantErr: true},
		{name: "spec wrong -00100.00", input: "-00100.00", wantErr: true},
		{name: "one decimal", input: "1.5", wantErr: true},
		{name: "no decimals", input: "1", wantErr: true},
		{name: "too large", input: "100000000.00", wantErr: true},
		{name: "comma", input: "1,00", wantErr: true},
		{name: "empty", input: "", wantErr: true},
		{name: "plus sign", input: "+1.00", wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := ParseAmount(tc.input)
			if (err != nil) != tc.wantErr || (err != nil && !errors.Is(err, ErrInvalidAmount)) {
				t.Fatalf("err = %v, wantErr %v", err, tc.wantErr)
			}
			if got != tc.want {
				t.Fatalf("ParseAmount(%q) = %d, want %d", tc.input, got, tc.want)
			}
		})
	}
}

func TestAmountValid(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name    string
		amount  Amount
		wantErr error
	}{
		{name: "maximum", amount: Halers(9999999999)},
		{name: "minimum", amount: Halers(-9999999999)},
		{name: "above maximum", amount: Halers(10000000000), wantErr: ErrAmountOutOfRange},
		{name: "below minimum", amount: Halers(-10000000000), wantErr: ErrAmountOutOfRange},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if err := tc.amount.Valid(); !errors.Is(err, tc.wantErr) {
				t.Fatalf("err = %v, want %v", err, tc.wantErr)
			}
		})
	}
}

func TestParseDecimal(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name    string
		input   string
		want    Amount
		wantErr error
	}{
		{name: "one decimal", input: "199.9", want: Halers(19990)},
		{name: "two decimals", input: "199.90", want: Halers(19990)},
		{name: "whole number", input: "200", want: Crowns(200)},
		{name: "exponent notation", input: "1.999E+2", want: Halers(19990)},
		{name: "surrounding spaces", input: " 12.5 ", want: Halers(1250)},
		{name: "half rounds up", input: "0.005", want: Halers(1)},
		{name: "below half rounds down", input: "0.0049", want: Halers(0)},
		{name: "negative half rounds away from zero", input: "-0.005", want: Halers(-1)},
		{name: "maximum", input: "99999999.99", want: Halers(9999999999)},
		{name: "out of range", input: "100000000", wantErr: ErrAmountOutOfRange},
		{name: "not a number", input: "12,50", wantErr: ErrInvalidAmount},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := ParseDecimal(tc.input)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("err = %v, want %v", err, tc.wantErr)
			}
			if got != tc.want {
				t.Fatalf("ParseDecimal(%q) = %d, want %d", tc.input, got, tc.want)
			}
		})
	}
}
