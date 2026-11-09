package eet

import (
	"context"
	"log/slog"
	"time"
)

const logMessage = "eet: registered sale attempt"

type attempt struct {
	msg      *Message
	resp     *Response
	err      error
	duration time.Duration
}

func WithLogger(l *slog.Logger) Option {
	return func(c *Client) error {
		c.logger = l
		return nil
	}
}

func (c *Client) logAttempt(a attempt) {
	if c.logger == nil {
		return
	}
	attrs := []slog.Attr{
		slog.String("environment", c.env.Name),
		slog.String("uuid", a.msg.UUID),
		slog.String("eic", a.msg.Sale.EIC),
		slog.Int("unit_id", a.msg.Sale.UnitID),
		slog.String("register_id", a.msg.Sale.RegisterID),
		slog.String("sequence_number", a.msg.Sale.SequenceNumber),
		slog.Bool("first_sending", a.msg.FirstSending),
		slog.Bool("verification", a.msg.Verification),
		slog.Duration("duration", a.duration),
	}
	if a.resp != nil {
		attrs = append(attrs,
			slog.String("transaction_id", a.resp.TransactionID),
			slog.String("pok", a.resp.POK),
			slog.Int("warnings", len(a.resp.Warnings)),
		)
	}
	level := slog.LevelInfo
	if a.err != nil {
		level = slog.LevelWarn
		attrs = append(attrs, slog.String("error", a.err.Error()), slog.Bool("should_resend", ShouldResend(a.err)))
	}
	c.logger.LogAttrs(context.Background(), level, logMessage, attrs...)
}
