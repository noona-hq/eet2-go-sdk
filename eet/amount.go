package eet

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
)

const (
	halersPerCrown            = 100
	maxAbsAmount       Amount = 99_999_999_99
	amountFractionSize        = 2
)

var amountPattern = regexp.MustCompile(`^((0|-?[1-9]\d{0,7})\.\d\d|-0\.(0[1-9]|[1-9]\d))$`)

type Amount int64

func Halers(h int64) Amount {
	return Amount(h)
}

func Crowns(c int64) Amount {
	return Amount(c * halersPerCrown)
}

func ParseAmount(s string) (Amount, error) {
	if !amountPattern.MatchString(s) {
		return 0, fmt.Errorf("eet: invalid amount %q", s)
	}
	digits := s
	neg := digits[0] == '-'
	if neg {
		digits = digits[1:]
	}
	point := len(digits) - amountFractionSize - 1
	whole, err := strconv.ParseInt(digits[:point], 10, 64)
	if err != nil {
		return 0, fmt.Errorf("eet: invalid amount %q: %w", s, err)
	}
	frac, err := strconv.ParseInt(digits[point+1:], 10, 64)
	if err != nil {
		return 0, fmt.Errorf("eet: invalid amount %q: %w", s, err)
	}
	a := Amount(whole*halersPerCrown + frac)
	if neg {
		return -a, nil
	}
	return a, nil
}

func (a Amount) Halers() int64 {
	return int64(a)
}

func (a Amount) Valid() error {
	if a > maxAbsAmount || a < -maxAbsAmount {
		return ErrAmountOutOfRange
	}
	return nil
}

func (a Amount) String() string {
	v := int64(a)
	sign := ""
	if v < 0 {
		sign = "-"
		v = -v
	}
	return fmt.Sprintf("%s%d.%02d", sign, v/halersPerCrown, v%halersPerCrown)
}

func (a Amount) MarshalText() ([]byte, error) {
	if err := a.Valid(); err != nil {
		return nil, err
	}
	return []byte(a.String()), nil
}

func (a *Amount) UnmarshalText(text []byte) error {
	v, err := ParseAmount(string(text))
	if err != nil {
		return err
	}
	*a = v
	return nil
}

func (a *Amount) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return fmt.Errorf("eet: amount must be a JSON string such as \"123.45\": %w", err)
	}
	return a.UnmarshalText([]byte(s))
}

func (a Amount) Neg() Amount {
	return -a
}
