package caeet

import (
	"bytes"
	"context"
	"crypto"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/noona-hq/eet2-go-sdk/eet"
)

type Environment struct {
	Name    string
	BaseURL string
}

var (
	Production = Environment{Name: "production", BaseURL: "https://ca.caeet.gov.cz/api"}
	Trial      = Environment{Name: "trial", BaseURL: "https://ca.zkus.caeet.gov.cz/api"}
	Test       = Environment{Name: "test", BaseURL: "https://ca.test.caeet.gov.cz/api"}
)

const (
	defaultHTTPTimeout = 30 * time.Second
	maxResponseSize    = 1 << 20
)

type Client struct {
	baseURL  string
	http     *http.Client
	cert     *x509.Certificate
	key      crypto.Signer
	lifetime time.Duration
}

type Option func(*Client) error

func WithHTTPClient(h *http.Client) Option {
	return func(c *Client) error {
		c.http = h
		return nil
	}
}

func WithTokenLifetime(d time.Duration) Option {
	return func(c *Client) error {
		if d <= 0 || d > MaxTokenLifetime {
			return fmt.Errorf("caeet: token lifetime must be within (0, %s]", MaxTokenLifetime)
		}
		c.lifetime = d
		return nil
	}
}

func New(env Environment, signer *eet.Signer, opts ...Option) (*Client, error) {
	if env.BaseURL == "" {
		return nil, errors.New("caeet: environment base URL is required")
	}
	if signer == nil {
		return nil, errors.New("caeet: signer is required")
	}
	c := &Client{
		baseURL:  strings.TrimRight(env.BaseURL, "/"),
		http:     &http.Client{Timeout: defaultHTTPTimeout},
		cert:     signer.Certificate(),
		key:      signer.Key(),
		lifetime: DefaultTokenLifetime,
	}
	for _, opt := range opts {
		if err := opt(c); err != nil {
			return nil, err
		}
	}
	return c, nil
}

type call struct {
	method     string
	path       string
	wantStatus int
}

func (c *Client) do(ctx context.Context, cl call, out any) (*http.Response, error) {
	token, err := c.Token()
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, cl.method, c.baseURL+cl.path, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")
	res, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	body, err := io.ReadAll(io.LimitReader(res.Body, maxResponseSize))
	if err != nil {
		return nil, err
	}
	if res.StatusCode != cl.wantStatus {
		return res, apiError(res.StatusCode, body)
	}
	if out == nil {
		return res, nil
	}
	if err := json.Unmarshal(body, out); err != nil {
		return res, fmt.Errorf("caeet: decoding response: %w", err)
	}
	return res, nil
}

func apiError(status int, body []byte) *APIError {
	var dto struct {
		Code           int    `json:"code"`
		Message        string `json:"message"`
		AdditionalInfo string `json:"additionalInfo"`
	}
	if err := json.Unmarshal(body, &dto); err != nil {
		return &APIError{StatusCode: status, Message: string(bytes.TrimSpace(body))}
	}
	return &APIError{StatusCode: status, Code: dto.Code, Message: dto.Message, AdditionalInfo: dto.AdditionalInfo}
}
