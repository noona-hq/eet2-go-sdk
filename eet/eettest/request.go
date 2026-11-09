package eettest

import (
	"encoding/xml"
	"fmt"
	"strconv"
	"time"

	"github.com/noona-hq/eet2-go-sdk/eet"
)

type Request struct {
	MessageUUID  string
	SentAt       time.Time
	FirstSending bool
	Verification bool
	Sale         eet.Sale
	SignerEIC    string
	POK          string
}

type xmlRequestBody struct {
	XMLName xml.Name `xml:"http://schemas.xmlsoap.org/soap/envelope/ Body"`
	Trzba   struct {
		Hlavicka struct {
			UUID         string `xml:"uuid_zpravy,attr"`
			SentAt       string `xml:"dat_odesl,attr"`
			FirstSending string `xml:"prvni_zaslani,attr"`
			Verification string `xml:"overeni,attr"`
		} `xml:"http://fs.gov.cz/eet/schema/v4 Hlavicka"`
		Data struct {
			EIC               string `xml:"eic_popl,attr"`
			DelegatingEIC     string `xml:"eic_poverujiciho,attr"`
			MultipleTaxpayers string `xml:"povereni_vice_popl,attr"`
			UnitID            string `xml:"id_jednotky,attr"`
			RegisterID        string `xml:"id_pokl,attr"`
			SequenceNumber    string `xml:"porad_cis,attr"`
			Time              string `xml:"dat_trzby,attr"`
			Total             string `xml:"celk_trzba,attr"`
			TopUp             string `xml:"urceno_cerp_zuct,attr"`
			Drawdown          string `xml:"cerp_zuct,attr"`
		} `xml:"http://fs.gov.cz/eet/schema/v4 Data"`
	} `xml:"http://fs.gov.cz/eet/schema/v4 Trzba"`
}

func parseRequest(canonicalBody []byte) (Request, error) {
	var body xmlRequestBody
	if err := xml.Unmarshal(canonicalBody, &body); err != nil {
		return Request{}, err
	}
	h, d := body.Trzba.Hlavicka, body.Trzba.Data
	sentAt, err := time.Parse(time.RFC3339, h.SentAt)
	if err != nil {
		return Request{}, fmt.Errorf("dat_odesl: %w", err)
	}
	saleTime, err := time.Parse(time.RFC3339, d.Time)
	if err != nil {
		return Request{}, fmt.Errorf("dat_trzby: %w", err)
	}
	unitID, err := strconv.Atoi(d.UnitID)
	if err != nil {
		return Request{}, fmt.Errorf("id_jednotky: %w", err)
	}
	total, err := eet.ParseAmount(d.Total)
	if err != nil {
		return Request{}, err
	}
	topUp, err := optionalAmount(d.TopUp)
	if err != nil {
		return Request{}, err
	}
	drawdown, err := optionalAmount(d.Drawdown)
	if err != nil {
		return Request{}, err
	}
	return Request{
		MessageUUID:  h.UUID,
		SentAt:       sentAt,
		FirstSending: parseBool(h.FirstSending),
		Verification: parseBool(h.Verification),
		Sale: eet.Sale{
			EIC:               d.EIC,
			DelegatingEIC:     d.DelegatingEIC,
			MultipleTaxpayers: parseBool(d.MultipleTaxpayers),
			UnitID:            unitID,
			RegisterID:        d.RegisterID,
			SequenceNumber:    d.SequenceNumber,
			Time:              saleTime,
			Total:             total,
			TopUp:             topUp,
			Drawdown:          drawdown,
		},
	}, nil
}

func optionalAmount(s string) (*eet.Amount, error) {
	if s == "" {
		return nil, nil
	}
	a, err := eet.ParseAmount(s)
	if err != nil {
		return nil, err
	}
	return &a, nil
}

func parseBool(s string) bool {
	return s == "true" || s == "1"
}
