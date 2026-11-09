package eet

import (
	"crypto/x509"
	"time"
)

const (
	saleTimeFutureTolerance = 2 * time.Hour
	saleTimeMaxAgeYears     = 2
	minUnitIDDigitsValue    = 10
	unitIDCheckDigitBase    = 10
	minUnitIDCheckDigit     = 1
	maxUnitIDCheckDigit     = 4
)

type WarningCode int

const (
	WarningEICMismatch          WarningCode = 1
	WarningDelegatingEICFormat  WarningCode = 2
	WarningSaleTimeInFuture     WarningCode = 4
	WarningSaleTimeTooOld       WarningCode = 5
	WarningUnitIDFormat         WarningCode = 6
	WarningDelegatingEICIsOwner WarningCode = 7
)

var warningMessages = map[WarningCode]string{
	WarningEICMismatch:          "EIC poplatnika v datove zprave se neshoduje s EIC v certifikatu",
	WarningDelegatingEICFormat:  "Chybny format EIC poverujiciho poplatnika",
	WarningSaleTimeInFuture:     "The date and time of the transaction are later than the date and time the message was received.",
	WarningSaleTimeTooOld:       "The date and time of transaction is far in the past",
	WarningUnitIDFormat:         "id_jednotky neodpovida formatem pridelenemu c. evidencni jednotky",
	WarningDelegatingEICIsOwner: "EIC poverujiciho se shoduje s EIC poplatnika",
}

type Warning struct {
	Code    WarningCode
	Message string
}

type LintOptions struct {
	Certificate *x509.Certificate
	Now         time.Time
	MinSaleTime time.Time
}

func (s Sale) Lint(opts LintOptions) []Warning {
	now := opts.Now
	if now.IsZero() {
		now = time.Now()
	}
	checks := []struct {
		code   WarningCode
		failed bool
	}{
		{WarningEICMismatch, opts.Certificate != nil && opts.Certificate.Subject.CommonName != s.EIC},
		{WarningDelegatingEICFormat, s.DelegatingEIC != "" && !eicPattern.MatchString(s.DelegatingEIC)},
		{WarningSaleTimeInFuture, s.Time.After(now.Add(saleTimeFutureTolerance))},
		{WarningSaleTimeTooOld, s.Time.Before(now.AddDate(-saleTimeMaxAgeYears, 0, 0)) || (!opts.MinSaleTime.IsZero() && s.Time.Before(opts.MinSaleTime))},
		{WarningUnitIDFormat, !validUnitIDFormat(s.UnitID)},
		{WarningDelegatingEICIsOwner, s.DelegatingEIC != "" && s.DelegatingEIC == s.EIC},
	}
	var w []Warning
	for _, c := range checks {
		if c.failed {
			w = append(w, Warning{Code: c.code, Message: warningMessages[c.code]})
		}
	}
	return w
}

func validUnitIDFormat(id int) bool {
	if id < minUnitIDDigitsValue {
		return false
	}
	last := id % unitIDCheckDigitBase
	return last >= minUnitIDCheckDigit && last <= maxUnitIDCheckDigit
}
