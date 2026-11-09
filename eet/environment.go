package eet

import "time"

type Environment struct {
	Name                    string
	URL                     string
	MinSaleTime             time.Time
	TransitionalMinSaleTime time.Time
}

var (
	Playground = Environment{
		Name:        "playground",
		URL:         "https://pg.trzbyeet.gov.cz/eet/services/EETServiceSOAP/v4",
		MinSaleTime: time.Date(2026, 7, 1, 0, 0, 0, 0, Prague),
	}
	Production = Environment{
		Name:                    "production",
		URL:                     "https://trzbyeet.gov.cz/eet/services/EETServiceSOAP/v4",
		MinSaleTime:             time.Date(2027, 1, 1, 0, 0, 0, 0, Prague),
		TransitionalMinSaleTime: time.Date(2026, 11, 1, 0, 0, 0, 0, Prague),
	}
)

func (e Environment) MinSaleTimeAt(now time.Time) time.Time {
	if !e.TransitionalMinSaleTime.IsZero() && now.Before(e.MinSaleTime) {
		return e.TransitionalMinSaleTime
	}
	return e.MinSaleTime
}
