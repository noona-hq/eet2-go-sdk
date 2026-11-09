package caeettest_test

import (
	"context"
	"crypto/x509"
	"errors"
	"net/http"
	"testing"

	"github.com/noona-hq/eet2-go-sdk/caeet"
	"github.com/noona-hq/eet2-go-sdk/caeet/caeettest"
	"github.com/noona-hq/eet2-go-sdk/eet"
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

func client(t *testing.T, srv *caeettest.Server, s *eet.Signer) *caeet.Client {
	t.Helper()
	c, err := caeet.New(srv.Environment(), s)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestServer(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name       string
		renewals   []caeettest.Renewal
		trust      bool
		wantErr    func(error) bool
		wantStatus int
	}{
		{name: "issued at once", trust: true, wantStatus: 1},
		{name: "issued after polling", renewals: []caeettest.Renewal{{PollsBeforeIssued: 1}}, trust: true, wantStatus: 2},
		{name: "rejected", renewals: []caeettest.Renewal{{RejectReason: "Selhání kontroly parametrů žádosti"}}, trust: true, wantErr: func(err error) bool { return errors.Is(err, caeet.ErrRejected) }},
		{name: "unknown certificate", wantErr: func(err error) bool {
			e, ok := errors.AsType[*caeet.APIError](err)
			return ok && e.StatusCode == http.StatusUnauthorized && e.Message == "Invalid certificate."
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			srv := caeettest.NewServer(t)
			srv.Enqueue(tc.renewals...)
			s := signer(t)
			if tc.trust {
				srv.Trust(s.Certificate())
			}
			var stored *caeet.Bundle
			bundle, err := client(t, srv, s).RenewCertificate(context.Background(), func(b *caeet.Bundle) error {
				stored = b
				return nil
			})
			if tc.wantErr != nil {
				if !tc.wantErr(err) {
					t.Fatalf("err = %v", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if stored != bundle {
				t.Fatal("the stored bundle is not the returned one")
			}
			renewed, err := bundle.Signer()
			if err != nil {
				t.Fatal(err)
			}
			if renewed.EIC() != s.EIC() || renewed.Certificate().Equal(s.Certificate()) || bundle.Certificate.SerialNumber != renewed.Certificate().SerialNumber.String() {
				t.Fatalf("renewed certificate %v", renewed.Certificate().Subject)
			}
			if _, err := renewed.Certificate().Verify(x509.VerifyOptions{Roots: rootPool(srv), KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}}); err != nil {
				t.Fatalf("renewed certificate is not issued by the test CA: %v", err)
			}
			statusCalls := 0
			for _, r := range srv.Requests() {
				if r.Method == http.MethodGet && r.Path != "/request/not-finished" {
					statusCalls++
				}
			}
			if statusCalls != tc.wantStatus {
				t.Fatalf("status calls = %d, want %d", statusCalls, tc.wantStatus)
			}
			if _, err := client(t, srv, renewed).RenewCertificate(context.Background(), func(*caeet.Bundle) error { return nil }); err != nil {
				t.Fatalf("a renewed certificate must be able to renew again: %v", err)
			}
		})
	}
}

func TestServerResumesAndAcknowledges(t *testing.T) {
	t.Parallel()
	srv := caeettest.NewServer(t)
	s := signer(t)
	srv.Trust(s.Certificate())
	c := client(t, srv, s)
	ctx := context.Background()

	reqID, err := c.Renew(ctx)
	if err != nil {
		t.Fatal(err)
	}
	pending, err := c.NotFinished(ctx)
	if err != nil || len(pending) != 1 || pending[0] != reqID {
		t.Fatalf("pending=%v err=%v", pending, err)
	}
	if _, err := c.WaitIssued(ctx, reqID); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if _, err := c.ClaimDownload(ctx, reqID); err != nil {
			t.Fatalf("claim-download must be repeatable until acknowledged: %v", err)
		}
	}
	if err := c.AckDownload(ctx, reqID); err != nil {
		t.Fatal(err)
	}
	_, err = c.ClaimDownload(ctx, reqID)
	if e, ok := errors.AsType[*caeet.APIError](err); !ok || e.StatusCode != http.StatusConflict {
		t.Fatalf("err = %v", err)
	}
	if pending, err := c.NotFinished(ctx); err != nil || len(pending) != 0 {
		t.Fatalf("pending=%v err=%v", pending, err)
	}
}

func rootPool(srv *caeettest.Server) *x509.CertPool {
	pool := x509.NewCertPool()
	pool.AddCert(srv.Root())
	return pool
}
