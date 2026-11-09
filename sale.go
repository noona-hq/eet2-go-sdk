package eet

import (
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const (
	MinUnitID = 1
	MaxUnitID = 999_999_999

	keySeparator = "|"
)

var (
	eicPattern      = regexp.MustCompile(`^CZ[0-9]{8,10}$`)
	string20Pattern = regexp.MustCompile(`^[0-9a-zA-Z\.,:;/#\-_ ]{1,20}$`)
	string25Pattern = regexp.MustCompile(`^[0-9a-zA-Z\.,:;/#\-_ ]{1,25}$`)
)

type Sale struct {
	EIC                  string
	DelegatingEIC        string
	MultipleTaxpayers    bool
	UnitID               int
	RegisterID           string
	SequenceNumber       string
	Time                 time.Time
	Total                Amount
	IntendedForDrawdown  *Amount
	DrawdownOrSettlement *Amount
}

func (s Sale) Validate() error {
	var errs []error
	if !eicPattern.MatchString(s.EIC) {
		errs = append(errs, &ValidationError{Field: "eic_popl", Reason: fmt.Sprintf("%q does not match %s", s.EIC, eicPattern)})
	}
	if s.DelegatingEIC != "" && !eicPattern.MatchString(s.DelegatingEIC) {
		errs = append(errs, &ValidationError{Field: "eic_poverujiciho", Reason: fmt.Sprintf("%q does not match %s", s.DelegatingEIC, eicPattern)})
	}
	if s.UnitID < MinUnitID || s.UnitID > MaxUnitID {
		errs = append(errs, &ValidationError{Field: "id_jednotky", Reason: fmt.Sprintf("%d is outside %d..%d", s.UnitID, MinUnitID, MaxUnitID)})
	}
	if !string20Pattern.MatchString(s.RegisterID) {
		errs = append(errs, &ValidationError{Field: "id_pokl", Reason: fmt.Sprintf("%q does not match %s", s.RegisterID, string20Pattern)})
	}
	if !string25Pattern.MatchString(s.SequenceNumber) {
		errs = append(errs, &ValidationError{Field: "porad_cis", Reason: fmt.Sprintf("%q does not match %s", s.SequenceNumber, string25Pattern)})
	}
	if err := validDateTime(s.Time); err != nil {
		errs = append(errs, &ValidationError{Field: "dat_trzby", Reason: err.Error()})
	}
	if err := s.Total.Valid(); err != nil {
		errs = append(errs, &ValidationError{Field: "celk_trzba", Reason: err.Error()})
	}
	if s.IntendedForDrawdown != nil {
		if err := s.IntendedForDrawdown.Valid(); err != nil {
			errs = append(errs, &ValidationError{Field: "urceno_cerp_zuct", Reason: err.Error()})
		}
	}
	if s.DrawdownOrSettlement != nil {
		if err := s.DrawdownOrSettlement.Valid(); err != nil {
			errs = append(errs, &ValidationError{Field: "cerp_zuct", Reason: err.Error()})
		}
	}
	return errors.Join(errs...)
}

func (s Sale) Key() string {
	return strings.Join([]string{
		s.EIC,
		strconv.Itoa(s.UnitID),
		s.RegisterID,
		s.SequenceNumber,
		FormatDateTime(s.Time),
		s.Total.String(),
	}, keySeparator)
}

func (s Sale) attrs() []attr {
	a := []attr{{name: "eic_popl", value: s.EIC}}
	if s.DelegatingEIC != "" {
		a = append(a, attr{name: "eic_poverujiciho", value: s.DelegatingEIC})
	}
	if s.MultipleTaxpayers {
		a = append(a, attr{name: "povereni_vice_popl", value: formatBool(true)})
	}
	a = append(a,
		attr{name: "id_jednotky", value: strconv.Itoa(s.UnitID)},
		attr{name: "id_pokl", value: s.RegisterID},
		attr{name: "porad_cis", value: s.SequenceNumber},
		attr{name: "dat_trzby", value: FormatDateTime(s.Time)},
		attr{name: "celk_trzba", value: s.Total.String()},
	)
	if s.IntendedForDrawdown != nil {
		a = append(a, attr{name: "urceno_cerp_zuct", value: s.IntendedForDrawdown.String()})
	}
	if s.DrawdownOrSettlement != nil {
		a = append(a, attr{name: "cerp_zuct", value: s.DrawdownOrSettlement.String()})
	}
	return a
}
