//go:build playground

package eet

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const playgroundTimeout = 10 * time.Second

func TestPlayground(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name   string
		mutate func(Sale) Sale
		send   func(*Client, context.Context, Sale) (*Response, error)
		check  func(t *testing.T, resp *Response, err error)
	}{
		{name: "send", mutate: func(s Sale) Sale { return s }, send: (*Client).Send, check: acceptedOnPlayground},
		{name: "resend", mutate: func(s Sale) Sale { s.Time = s.Time.Add(-30 * time.Minute); return s }, send: (*Client).Resend, check: acceptedOnPlayground},
		{name: "storno drawing down a top-up", mutate: func(s Sale) Sale {
			s.Total, s.Drawdown = Halers(-12100), new(Halers(-12100))
			return s
		}, send: (*Client).Send, check: acceptedOnPlayground},
		{name: "verification mode", mutate: func(s Sale) Sale { return s }, send: (*Client).Verify, check: func(t *testing.T, resp *Response, err error) {
			if err != nil || !resp.VerificationSucceeded() || !resp.Test {
				t.Fatalf("resp=%+v err=%v", resp, err)
			}
		}},
		{name: "non-critical warnings", mutate: func(s Sale) Sale {
			s.EIC, s.DelegatingEIC, s.UnitID = "CZ683555118", "CZ683555118", 5
			return s
		}, send: (*Client).Send, check: func(t *testing.T, resp *Response, err error) {
			acceptedOnPlayground(t, resp, err)
			if len(resp.Warnings) != 3 {
				t.Fatalf("warnings %+v", resp.Warnings)
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			c := newTestClient(t, Playground.URL, WithTimeout(playgroundTimeout))
			sale := testSale()
			sale.SequenceNumber = strings.ReplaceAll(tc.name, " ", "-")[:min(len(tc.name), 12)] + time.Now().Format("150405.000")
			resp, err := tc.send(c, context.Background(), tc.mutate(sale))
			dumpResponse(t, resp)
			tc.check(t, resp, err)
		})
	}
}

func acceptedOnPlayground(t *testing.T, resp *Response, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
	if !resp.Accepted() || !resp.Test || !resp.Signed || !strings.HasSuffix(resp.POK, "-ff") {
		t.Fatalf("unexpected response %+v", resp)
	}
	t.Logf("POK=%s tx=%s warnings=%v", resp.POK, resp.TransactionID, resp.Warnings)
}

func dumpResponse(t *testing.T, resp *Response) {
	t.Helper()
	dir := os.Getenv("EET_DUMP_DIR")
	if dir == "" || resp == nil {
		return
	}
	if err := os.WriteFile(filepath.Join(dir, strings.ReplaceAll(t.Name(), "/", "_")+".xml"), resp.Raw, 0o644); err != nil {
		t.Fatal(err)
	}
}
