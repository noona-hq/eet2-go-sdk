package caeet

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"time"

	"github.com/noona-hq/eet2-go-sdk/eet"
)

const retryAfterHeader = "Retry-After"

type State string

const (
	StateInProcess  State = "INPROCESS"
	StateIssued     State = "ISSUED"
	StateDelivering State = "DELIVERING"
	StateFinished   State = "FINISHED"
	StateRejected   State = "REJECTED"
)

type CertificateState string

const (
	CertificateValid   CertificateState = "VALID"
	CertificateExpired CertificateState = "EXPIRED"
	CertificateRevoked CertificateState = "REVOKED"
	CertificateOnCRL   CertificateState = "ON_CRL"
)

type requestAction string

const (
	actionStatus        requestAction = "status"
	actionClaimDownload requestAction = "claim-download"
	actionAckDownload   requestAction = "ack-download"
)

var (
	reqIDPattern    = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
	dateTimeLayouts = []string{time.RFC3339Nano, "2006-01-02 15:04:05Z07:00", "2006-01-02 15:04:05.999999999Z07:00"}
)

type RequestStatus struct {
	RequestID      string
	State          State
	PollAfter      time.Duration
	RejectedReason string
}

type Certificate struct {
	SerialNumber   string
	ValidFrom      time.Time
	ValidTo        time.Time
	State          CertificateState
	RevocationTime time.Time
	Description    string
	Email          string
}

type Bundle struct {
	PKCS12      []byte
	Password    string
	Certificate Certificate
}

func (b *Bundle) Signer() (*eet.Signer, error) {
	return eet.LoadPKCS12(b.PKCS12, b.Password)
}

func requestPath(reqID string, action requestAction) (string, error) {
	if !reqIDPattern.MatchString(reqID) {
		return "", fmt.Errorf("caeet: invalid request id %q", reqID)
	}
	return "/request/" + reqID + "/" + string(action), nil
}

func (c *Client) Renew(ctx context.Context) (string, error) {
	var out struct {
		ReqID string `json:"reqId"`
	}
	if _, err := c.do(ctx, call{method: http.MethodPost, path: "/request/renew", wantStatus: http.StatusCreated}, &out); err != nil {
		return "", err
	}
	if out.ReqID == "" {
		return "", errors.New("caeet: renew response has no reqId")
	}
	return out.ReqID, nil
}

func (c *Client) Status(ctx context.Context, reqID string) (*RequestStatus, error) {
	path, err := requestPath(reqID, actionStatus)
	if err != nil {
		return nil, err
	}
	var out struct {
		ReqID            string `json:"reqId"`
		State            State  `json:"state"`
		PollAfterSeconds int    `json:"pollAfterSeconds"`
		RejectedReason   string `json:"rejectedReason"`
	}
	res, err := c.do(ctx, call{method: http.MethodGet, path: path, wantStatus: http.StatusOK}, &out)
	if err != nil {
		return nil, err
	}
	pollAfter := time.Duration(out.PollAfterSeconds) * time.Second
	if s, err := strconv.Atoi(res.Header.Get(retryAfterHeader)); pollAfter == 0 && err == nil && s > 0 {
		pollAfter = time.Duration(s) * time.Second
	}
	return &RequestStatus{
		RequestID:      out.ReqID,
		State:          out.State,
		PollAfter:      pollAfter,
		RejectedReason: out.RejectedReason,
	}, nil
}

func (c *Client) ClaimDownload(ctx context.Context, reqID string) (*Bundle, error) {
	path, err := requestPath(reqID, actionClaimDownload)
	if err != nil {
		return nil, err
	}
	var out struct {
		PKCS12      []byte `json:"pkcs12"`
		Password    string `json:"password"`
		Certificate struct {
			SN             string           `json:"sn"`
			ValidFrom      string           `json:"validFrom"`
			ValidTo        string           `json:"validTo"`
			State          CertificateState `json:"state"`
			RevocationTime string           `json:"revocationTime"`
			Description    string           `json:"description"`
			Email          string           `json:"email"`
		} `json:"certificate"`
	}
	if _, err := c.do(ctx, call{method: http.MethodPost, path: path, wantStatus: http.StatusOK}, &out); err != nil {
		return nil, err
	}
	if len(out.PKCS12) == 0 || out.Password == "" {
		return nil, errors.New("caeet: claim-download response is missing PKCS#12 or password")
	}
	validFrom, err := parseDateTime(out.Certificate.ValidFrom)
	if err != nil {
		return nil, fmt.Errorf("caeet: validFrom: %w", err)
	}
	validTo, err := parseDateTime(out.Certificate.ValidTo)
	if err != nil {
		return nil, fmt.Errorf("caeet: validTo: %w", err)
	}
	var revokedAt time.Time
	if out.Certificate.RevocationTime != "" {
		if revokedAt, err = parseDateTime(out.Certificate.RevocationTime); err != nil {
			return nil, fmt.Errorf("caeet: revocationTime: %w", err)
		}
	}
	return &Bundle{
		PKCS12:   out.PKCS12,
		Password: out.Password,
		Certificate: Certificate{
			SerialNumber:   out.Certificate.SN,
			ValidFrom:      validFrom,
			ValidTo:        validTo,
			State:          out.Certificate.State,
			RevocationTime: revokedAt,
			Description:    out.Certificate.Description,
			Email:          out.Certificate.Email,
		},
	}, nil
}

func (c *Client) AckDownload(ctx context.Context, reqID string) error {
	path, err := requestPath(reqID, actionAckDownload)
	if err != nil {
		return err
	}
	_, err = c.do(ctx, call{method: http.MethodPost, path: path, wantStatus: http.StatusNoContent}, nil)
	return err
}

func (c *Client) NotFinished(ctx context.Context) ([]string, error) {
	var out struct {
		Count int      `json:"count"`
		Data  []string `json:"data"`
	}
	if _, err := c.do(ctx, call{method: http.MethodGet, path: "/request/not-finished", wantStatus: http.StatusOK}, &out); err != nil {
		return nil, err
	}
	return out.Data, nil
}

func parseDateTime(s string) (time.Time, error) {
	for _, layout := range dateTimeLayouts {
		if t, err := time.Parse(layout, s); err == nil {
			return t, nil
		}
	}
	return time.Time{}, fmt.Errorf("invalid date-time %q", s)
}
