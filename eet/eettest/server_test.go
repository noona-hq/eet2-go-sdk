package eettest_test

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/noona-hq/eet2-go-sdk/eet"
	"github.com/noona-hq/eet2-go-sdk/eet/eettest"
	"github.com/noona-hq/eet2-go-sdk/internal/fixtures"
)

func signer(t *testing.T) *eet.Signer {
	t.Helper()
	s, err := eet.LoadPKCS12(fixtures.PlaygroundP12(fixtures.EICLegalEntity), fixtures.PlaygroundPassword())
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func sale() eet.Sale {
	return eet.Sale{
		EIC:            fixtures.EICLegalEntity,
		UnitID:         24,
		RegisterID:     "SDK-TEST",
		SequenceNumber: "2027/1",
		Time:           time.Now().In(eet.Prague).Truncate(time.Second),
		Total:          eet.Crowns(250),
		Drawdown:       new(eet.Crowns(100)),
	}
}

func TestServer(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name    string
		replies []eettest.Reply
		send    func(*eet.Client, context.Context, eet.Sale) (*eet.Response, error)
		opts    []eet.Option
		check   func(t *testing.T, resp *eet.Response, err error, got eettest.Request)
	}{
		{
			name: "accepts by default",
			send: (*eet.Client).Send,
			check: func(t *testing.T, resp *eet.Response, err error, got eettest.Request) {
				if err != nil {
					t.Fatal(err)
				}
				if !resp.Accepted() || !resp.Signed || !resp.Test || !strings.HasSuffix(resp.POK, "-ff") || resp.POK != got.POK {
					t.Fatalf("response %+v, request %+v", resp, got)
				}
				if !got.FirstSending || got.Verification || got.SignerEIC != fixtures.EICLegalEntity || got.MessageUUID != resp.MessageUUID {
					t.Fatalf("request %+v", got)
				}
			},
		},
		{
			name:    "accepts with warnings",
			replies: []eettest.Reply{eettest.Accept(eet.Warning{Code: eet.WarningUnitIDFormat, Message: "id_jednotky <x> & y"})},
			send:    (*eet.Client).Send,
			check: func(t *testing.T, resp *eet.Response, err error, _ eettest.Request) {
				if err != nil {
					t.Fatal(err)
				}
				if len(resp.Warnings) != 1 || resp.Warnings[0].Code != eet.WarningUnitIDFormat || resp.Warnings[0].Message != "id_jednotky <x> & y" {
					t.Fatalf("warnings %+v", resp.Warnings)
				}
			},
		},
		{
			name: "records repeated sending",
			send: (*eet.Client).Resend,
			check: func(t *testing.T, _ *eet.Response, err error, got eettest.Request) {
				if err != nil || got.FirstSending {
					t.Fatalf("err=%v request=%+v", err, got)
				}
			},
		},
		{
			name: "verification mode",
			send: (*eet.Client).Verify,
			check: func(t *testing.T, resp *eet.Response, err error, got eettest.Request) {
				if err != nil || !resp.VerificationSucceeded() || resp.Accepted() || !got.Verification || got.POK != "" {
					t.Fatalf("resp=%+v err=%v request=%+v", resp, err, got)
				}
			},
		},
		{
			name:    "rejected message",
			replies: []eettest.Reply{eettest.Reject(eet.CodeInvalidEIC, "EICpoplatnika ma chybnou strukturu")},
			send:    (*eet.Client).Send,
			check: func(t *testing.T, _ *eet.Response, err error, _ eettest.Request) {
				re, ok := errors.AsType[*eet.ResponseError](err)
				if !ok || re.Code != eet.CodeInvalidEIC || eet.ShouldResend(err) {
					t.Fatalf("err = %v", err)
				}
			},
		},
		{
			name:    "temporary error",
			replies: []eettest.Reply{eettest.TemporaryError()},
			send:    (*eet.Client).Send,
			check: func(t *testing.T, _ *eet.Response, err error, _ eettest.Request) {
				re, ok := errors.AsType[*eet.ResponseError](err)
				if !ok || !re.Temporary() || !eet.ShouldResend(err) {
					t.Fatalf("err = %v", err)
				}
			},
		},
		{
			name:    "service unavailable",
			replies: []eettest.Reply{eettest.Unavailable()},
			send:    (*eet.Client).Send,
			check: func(t *testing.T, _ *eet.Response, err error, _ eettest.Request) {
				he, ok := errors.AsType[*eet.HTTPError](err)
				if !ok || he.StatusCode != http.StatusServiceUnavailable || !eet.ShouldResend(err) {
					t.Fatalf("err = %v", err)
				}
			},
		},
		{
			name:    "slower than the response time limit",
			replies: []eettest.Reply{eettest.Accept().After(eet.MinTimeout + time.Second)},
			send:    (*eet.Client).Send,
			opts:    []eet.Option{eet.WithTimeout(eet.MinTimeout)},
			check: func(t *testing.T, _ *eet.Response, err error, _ eettest.Request) {
				te, ok := errors.AsType[*eet.TransportError](err)
				if !ok || !te.Timeout || te.MessageUUID == "" || !eet.ShouldResend(err) {
					t.Fatalf("err = %#v", err)
				}
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			srv := eettest.NewServer(t)
			srv.Enqueue(tc.replies...)
			client, err := srv.NewClient(signer(t), tc.opts...)
			if err != nil {
				t.Fatal(err)
			}
			sent := sale()
			resp, err := tc.send(client, context.Background(), sent)
			reqs := srv.Requests()
			if len(reqs) != 1 {
				t.Fatalf("server received %d requests", len(reqs))
			}
			if reqs[0].Sale.Key() != sent.Key() || *reqs[0].Sale.Drawdown != *sent.Drawdown {
				t.Fatalf("server received %+v, sent %+v", reqs[0].Sale, sent)
			}
			tc.check(t, resp, err, reqs[0])
		})
	}
}

func TestStart(t *testing.T) {
	t.Parallel()
	srv, err := eettest.Start()
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	client, err := srv.NewClient(signer(t))
	if err != nil {
		t.Fatal(err)
	}
	resp, err := client.Send(context.Background(), sale())
	if err != nil || !resp.Accepted() || resp.SigningCertificate.Subject.Organization[0] != srv.SignerOrganization() {
		t.Fatalf("resp=%+v err=%v", resp, err)
	}
}

func TestServerResponsesAreTrustedOnlyWithClientOptions(t *testing.T) {
	t.Parallel()
	srv := eettest.NewServer(t)
	client, err := eet.NewClient(srv.Environment(), signer(t))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Send(context.Background(), sale()); !errors.Is(err, eet.ErrInvalidSignature) {
		t.Fatalf("err = %v", err)
	}
}

func TestServerRejectsUnsignedRequests(t *testing.T) {
	t.Parallel()
	srv := eettest.NewServer(t)
	res, err := http.Post(srv.URL(), "text/xml", strings.NewReader(`<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/"><soapenv:Body/></soapenv:Envelope>`))
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	body, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), `kod="4"`) {
		t.Fatalf("response %s", body)
	}
}
