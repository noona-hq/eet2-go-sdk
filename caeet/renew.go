package caeet

import (
	"context"
	"fmt"
	"time"
)

const (
	defaultPollInterval = 2 * time.Second
)

func (c *Client) WaitIssued(ctx context.Context, reqID string) (*RequestStatus, error) {
	for {
		st, err := c.Status(ctx, reqID)
		if err != nil {
			return nil, err
		}
		switch st.State {
		case StateIssued, StateDelivering:
			return st, nil
		case StateRejected:
			return st, fmt.Errorf("%w: %s", ErrRejected, st.RejectedReason)
		case StateInProcess:
		default:
			return st, fmt.Errorf("%w: %s", ErrUnexpectedState, st.State)
		}
		wait := st.PollAfter
		if wait <= 0 {
			wait = defaultPollInterval
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(wait):
		}
	}
}

func (c *Client) RenewCertificate(ctx context.Context, store func(*Bundle) error) (*Bundle, error) {
	reqID, err := c.pendingOrNewRequest(ctx)
	if err != nil {
		return nil, err
	}
	if _, err := c.WaitIssued(ctx, reqID); err != nil {
		return nil, err
	}
	bundle, err := c.ClaimDownload(ctx, reqID)
	if err != nil {
		return nil, err
	}
	if _, err := bundle.Signer(); err != nil {
		return nil, fmt.Errorf("caeet: downloaded PKCS#12 is unusable: %w", err)
	}
	if err := store(bundle); err != nil {
		return nil, fmt.Errorf("caeet: storing renewed certificate: %w", err)
	}
	if err := c.AckDownload(ctx, reqID); err != nil {
		return bundle, err
	}
	return bundle, nil
}

func (c *Client) pendingOrNewRequest(ctx context.Context) (string, error) {
	pending, err := c.NotFinished(ctx)
	if err != nil {
		return "", err
	}
	if len(pending) > 0 {
		return pending[0], nil
	}
	return c.Renew(ctx)
}
