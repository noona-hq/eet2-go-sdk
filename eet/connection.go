package eet

import (
	"context"
	"errors"
	"time"
)

const (
	connectionCheckSequencePrefix = "OVERENI/"
	connectionCheckSequenceLayout = "20060102150405"
)

var ErrUnexpectedVerificationResponse = errors.New("eet: verification message was not confirmed with error code 0")

type Register struct {
	EIC               string
	DelegatingEIC     string
	MultipleTaxpayers bool
	UnitID            int
	RegisterID        string
}

func (r Register) Sale(at time.Time) Sale {
	return Sale{
		EIC:               r.EIC,
		DelegatingEIC:     r.DelegatingEIC,
		MultipleTaxpayers: r.MultipleTaxpayers,
		UnitID:            r.UnitID,
		RegisterID:        r.RegisterID,
		SequenceNumber:    connectionCheckSequencePrefix + at.In(Prague).Format(connectionCheckSequenceLayout),
		Time:              at.In(Prague).Truncate(time.Second),
	}
}

func (c *Client) CheckConnection(ctx context.Context, r Register) error {
	resp, err := c.Verify(ctx, r.Sale(time.Now()))
	if err != nil {
		return err
	}
	if !resp.VerificationSucceeded() {
		return ErrUnexpectedVerificationResponse
	}
	return nil
}
