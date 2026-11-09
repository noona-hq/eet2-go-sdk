package eet

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net/http"
	"sync/atomic"
	"time"
)

const (
	PlaygroundURL = "https://pg.trzbyeet.gov.cz/eet/services/EETServiceSOAP/v4"
	ProductionURL = "https://trzbyeet.gov.cz/eet/services/EETServiceSOAP/v4"

	MinTimeout     = 2 * time.Second
	DefaultTimeout = 3 * time.Second

	maxIdleConnsPerHost = 16
	idleConnTimeout     = 60 * time.Second
)

type Client struct {
	url       string
	http      *http.Client
	signer    atomic.Pointer[Signer]
	timeout   time.Duration
	verify    bool
	certCheck func(*x509.Certificate) error
}

func NewClient(url string, signer *Signer, opts ...Option) (*Client, error) {
	if signer == nil {
		return nil, errors.New("eet: signer is required")
	}
	c := &Client{
		url:       url,
		timeout:   DefaultTimeout,
		verify:    true,
		certCheck: CheckResponseSignerOrganization,
	}
	c.signer.Store(signer)
	for _, opt := range opts {
		if err := opt(c); err != nil {
			return nil, err
		}
	}
	if c.http == nil {
		c.http = &http.Client{Transport: newTransport()}
	}
	return c, nil
}

func newTransport() *http.Transport {
	return &http.Transport{
		Proxy:               http.ProxyFromEnvironment,
		TLSClientConfig:     &tls.Config{MinVersion: tls.VersionTLS12},
		ForceAttemptHTTP2:   false,
		TLSNextProto:        map[string]func(string, *tls.Conn) http.RoundTripper{},
		MaxIdleConnsPerHost: maxIdleConnsPerHost,
		IdleConnTimeout:     idleConnTimeout,
	}
}

func (c *Client) SetSigner(s *Signer) {
	if s != nil {
		c.signer.Store(s)
	}
}

func (c *Client) Signer() *Signer {
	return c.signer.Load()
}

type SendOptions struct {
	Repeat       bool
	Verification bool
}

func (c *Client) Prepare(sale Sale, opts SendOptions) (*Message, error) {
	if err := sale.Validate(); err != nil {
		return nil, err
	}
	signer := c.signer.Load()
	now := time.Now()
	if !signer.ValidAt(now) {
		return nil, ErrCertificateNotValid
	}
	uuid, err := newUUID()
	if err != nil {
		return nil, err
	}
	ids, err := newSecurityIDs()
	if err != nil {
		return nil, err
	}
	h := header{
		uuid:         uuid,
		sentAt:       now.In(Prague).Truncate(time.Second),
		firstSending: !opts.Repeat,
	}
	if opts.Verification {
		h.verification = new(true)
	}
	if err := h.validate(); err != nil {
		return nil, err
	}
	raw, err := buildEnvelope(signer, h, sale, ids)
	if err != nil {
		return nil, err
	}
	if len(raw) > MaxMessageSize {
		return nil, ErrMessageTooLarge
	}
	return &Message{
		UUID:         uuid,
		SentAt:       h.sentAt,
		FirstSending: h.firstSending,
		Verification: opts.Verification,
		Sale:         sale,
		XML:          raw,
		client:       c,
	}, nil
}

func (c *Client) Send(ctx context.Context, sale Sale) (*Response, error) {
	return c.prepareAndSend(ctx, sale, SendOptions{})
}

func (c *Client) Resend(ctx context.Context, sale Sale) (*Response, error) {
	return c.prepareAndSend(ctx, sale, SendOptions{Repeat: true})
}

func (c *Client) Verify(ctx context.Context, sale Sale) (*Response, error) {
	return c.prepareAndSend(ctx, sale, SendOptions{Verification: true})
}

func (c *Client) prepareAndSend(ctx context.Context, sale Sale, opts SendOptions) (*Response, error) {
	msg, err := c.Prepare(sale, opts)
	if err != nil {
		return nil, err
	}
	return msg.Send(ctx)
}
