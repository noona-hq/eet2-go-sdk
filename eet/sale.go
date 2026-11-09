package eet

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/noona-hq/eet2-go-sdk/internal/wssec"
)

const (
	MinUnitID = 1
	MaxUnitID = 999_999_999

	ResendPeriod = 48 * time.Hour

	keySeparator = "|"
)

var (
	eicPattern      = regexp.MustCompile(`^CZ[0-9]{8,10}$`)
	string20Pattern = regexp.MustCompile(`^[0-9a-zA-Z\.,:;/#\-_ ]{1,20}$`)
	string25Pattern = regexp.MustCompile(`^[0-9a-zA-Z\.,:;/#\-_ ]{1,25}$`)
)

type Sale struct {
	EIC               string    `json:"eic"`
	DelegatingEIC     string    `json:"delegatingEic,omitempty"`
	MultipleTaxpayers bool      `json:"multipleTaxpayers,omitempty"`
	UnitID            int       `json:"unitId"`
	RegisterID        string    `json:"registerId"`
	SequenceNumber    string    `json:"sequenceNumber"`
	Time              time.Time `json:"time"`
	Total             Amount    `json:"total"`
	TopUp             *Amount   `json:"topUp,omitempty"`
	Drawdown          *Amount   `json:"drawdown,omitempty"`
}

type Reversal struct {
	Time           time.Time
	SequenceNumber string
}

func (s Sale) Reversal(r Reversal) Sale {
	reversed := s
	reversed.Time = r.Time
	reversed.SequenceNumber = r.SequenceNumber
	reversed.Total = s.Total.Neg()
	if s.TopUp != nil {
		reversed.TopUp = new(s.TopUp.Neg())
	}
	if s.Drawdown != nil {
		reversed.Drawdown = new(s.Drawdown.Neg())
	}
	return reversed
}

func (s Sale) ResendDeadline() time.Time {
	return s.Time.Add(ResendPeriod)
}

func (s Sale) Validate() error {
	var errs ValidationErrors
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
	if s.TopUp != nil {
		if err := s.TopUp.Valid(); err != nil {
			errs = append(errs, &ValidationError{Field: "urceno_cerp_zuct", Reason: err.Error()})
		}
	}
	if s.Drawdown != nil {
		if err := s.Drawdown.Valid(); err != nil {
			errs = append(errs, &ValidationError{Field: "cerp_zuct", Reason: err.Error()})
		}
	}
	if len(errs) == 0 {
		return nil
	}
	return errs
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

func (s Sale) attrs() []wssec.Attr {
	a := []wssec.Attr{{Name: "eic_popl", Value: s.EIC}}
	if s.DelegatingEIC != "" {
		a = append(a, wssec.Attr{Name: "eic_poverujiciho", Value: s.DelegatingEIC})
	}
	if s.MultipleTaxpayers {
		a = append(a, wssec.Attr{Name: "povereni_vice_popl", Value: formatBool(true)})
	}
	a = append(a,
		wssec.Attr{Name: "id_jednotky", Value: strconv.Itoa(s.UnitID)},
		wssec.Attr{Name: "id_pokl", Value: s.RegisterID},
		wssec.Attr{Name: "porad_cis", Value: s.SequenceNumber},
		wssec.Attr{Name: "dat_trzby", Value: FormatDateTime(s.Time)},
		wssec.Attr{Name: "celk_trzba", Value: s.Total.String()},
	)
	if s.TopUp != nil {
		a = append(a, wssec.Attr{Name: "urceno_cerp_zuct", Value: s.TopUp.String()})
	}
	if s.Drawdown != nil {
		a = append(a, wssec.Attr{Name: "cerp_zuct", Value: s.Drawdown.String()})
	}
	return a
}
