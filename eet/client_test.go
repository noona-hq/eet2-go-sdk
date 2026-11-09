package eet

import (
	"bytes"
	"context"
	"crypto/x509"
	"errors"
	"net/http"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/noona-hq/eet2-go-sdk/internal/fixtures"
	"github.com/noona-hq/eet2-go-sdk/internal/wssec"
)

var pokFirstDigitPattern = regexp.MustCompile(`pok="([0-9a-f])`)

func TestNewClient(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name       string
		env        Environment
		opts       func(*testing.T) []Option
		wantErr    error
		wantSigner string
	}{
		{name: "without signer", env: Playground, opts: func(*testing.T) []Option { return nil }},
		{name: "with signer", env: Playground, opts: func(t *testing.T) []Option { return []Option{WithSigner(playgroundSigner(t, testEIC))} }, wantSigner: testEIC},
		{name: "legal minimum timeout", env: Playground, opts: func(*testing.T) []Option { return []Option{WithTimeout(MinTimeout)} }},
		{name: "missing environment URL", env: Environment{Name: "empty"}, opts: func(*testing.T) []Option { return nil }, wantErr: ErrNoEnvironmentURL},
		{name: "timeout below legal minimum", env: Playground, opts: func(*testing.T) []Option { return []Option{WithTimeout(MinTimeout - time.Millisecond)} }, wantErr: ErrTimeoutTooShort},
		{name: "nil signer", env: Playground, opts: func(*testing.T) []Option { return []Option{WithSigner(nil)} }, wantErr: ErrNoSigner},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			c, err := NewClient(tc.env, tc.opts(t)...)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("err = %v, want %v", err, tc.wantErr)
			}
			if tc.wantErr != nil {
				return
			}
			if got := c.Signer(); (got == nil) != (tc.wantSigner == "") || (got != nil && got.EIC() != tc.wantSigner) {
				t.Fatalf("signer = %v, want %q", got, tc.wantSigner)
			}
		})
	}
}

func TestPrepare(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name    string
		signer  func(*testing.T) *Signer
		sale    func() Sale
		opts    SendOptions
		wantErr error
		want    []string
		absent  []string
	}{
		{
			name:   "first sending",
			signer: func(t *testing.T) *Signer { return playgroundSigner(t, testEIC) },
			sale:   testSale,
			want:   []string{`prvni_zaslani="true"`, `celk_trzba="123.45"`, `id_pokl="SDK-TEST"`},
			absent: []string{"overeni", "eic_poverujiciho", "povereni_vice_popl", "urceno_cerp_zuct", "cerp_zuct"},
		},
		{
			name:   "repeated sending",
			signer: func(t *testing.T) *Signer { return playgroundSigner(t, testEIC) },
			sale:   testSale,
			opts:   SendOptions{Repeat: true},
			want:   []string{`prvni_zaslani="false"`},
			absent: []string{"overeni"},
		},
		{
			name:   "verification mode",
			signer: func(t *testing.T) *Signer { return playgroundSigner(t, testEIC) },
			sale:   testSale,
			opts:   SendOptions{Verification: true},
			want:   []string{`prvni_zaslani="true"`, `overeni="true"`},
		},
		{
			name:   "storno drawing down a top-up",
			signer: func(t *testing.T) *Signer { return playgroundSigner(t, testEIC) },
			sale: func() Sale {
				s := testSale()
				s.Total, s.Drawdown = Halers(-12100), new(Halers(-12100))
				return s
			},
			want: []string{`celk_trzba="-121.00"`, `cerp_zuct="-121.00"`},
		},
		{
			name:   "invalid sale",
			signer: func(t *testing.T) *Signer { return playgroundSigner(t, testEIC) },
			sale: func() Sale {
				s := testSale()
				s.RegisterID = "Pokladna č. 1"
				return s
			},
			wantErr: &ValidationError{Field: "id_pokl"},
		},
		{
			name:    "expired certificate",
			signer:  expiredSigner,
			sale:    testSale,
			wantErr: ErrCertificateNotValid,
		},
		{
			name:    "no signer",
			signer:  func(*testing.T) *Signer { return nil },
			sale:    testSale,
			wantErr: ErrNoSigner,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var opts []Option
			if signer := tc.signer(t); signer != nil {
				opts = append(opts, WithSigner(signer))
			}
			c, err := NewClient(Playground, opts...)
			if err != nil {
				t.Fatal(err)
			}
			before := time.Now().Truncate(time.Second)
			msg, err := c.Prepare(tc.sale(), tc.opts)
			if ve, ok := errors.AsType[*ValidationError](tc.wantErr); ok {
				if got, ok := errors.AsType[*ValidationError](err); !ok || got.Field != ve.Field {
					t.Fatalf("err = %v, want validation error on %s", err, ve.Field)
				}
				return
			}
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("err = %v, want %v", err, tc.wantErr)
			}
			if tc.wantErr != nil {
				return
			}
			if !uuidPattern.MatchString(msg.UUID) || msg.UUID[14] != '4' {
				t.Errorf("UUID %q is not a version 4 UUID", msg.UUID)
			}
			if msg.SentAt.Before(before) || msg.SentAt.After(time.Now()) || msg.SentAt.Location() != Prague {
				t.Errorf("SentAt = %v", msg.SentAt)
			}
			if msg.FirstSending == tc.opts.Repeat || msg.Verification != tc.opts.Verification {
				t.Errorf("message flags %+v for %+v", msg, tc.opts)
			}
			if _, err := wssec.Verify(msg.XML); err != nil {
				t.Errorf("prepared message does not verify: %v", err)
			}
			for _, w := range append(tc.want, `uuid_zpravy="`+msg.UUID+`"`, `dat_odesl="`+FormatDateTime(msg.SentAt)+`"`) {
				if !bytes.Contains(msg.XML, []byte(w)) {
					t.Errorf("message lacks %s", w)
				}
			}
			for _, a := range tc.absent {
				if bytes.Contains(msg.XML, []byte(a)) {
					t.Errorf("message must not carry %s", a)
				}
			}
		})
	}
}

func TestPrepareRepeatKeepsDataWithFreshHeader(t *testing.T) {
	t.Parallel()
	c := newTestClient(t, Playground.URL)
	sale := testSale()
	first, err := c.Prepare(sale, SendOptions{})
	if err != nil {
		t.Fatal(err)
	}
	repeat, err := c.Prepare(sale, SendOptions{Repeat: true})
	if err != nil {
		t.Fatal(err)
	}
	if first.UUID == repeat.UUID {
		t.Fatal("a repeated sending must use a new uuid_zpravy")
	}
	data := func(m *Message) []byte { return m.XML[bytes.Index(m.XML, []byte("<v4:Data")):] }
	if !bytes.Equal(data(first), data(repeat)) {
		t.Fatal("a repeated sending must keep Data unchanged")
	}
}

type sendResult struct {
	msg  *Message
	resp *Response
	err  error
	req  *http.Request
	body []byte
}

func TestMessageSend(t *testing.T) {
	t.Parallel()
	signedAck := func(*testing.T) []byte { return fixtures.PlaygroundResponse(fixtures.ResponseSend) }
	for _, tc := range []struct {
		name            string
		response        func(t *testing.T) fakeResponse
		opts            []Option
		sendOpts        SendOptions
		answersThisUUID func(t *testing.T) string
		check           func(t *testing.T, r sendResult)
	}{
		{
			name: "signed acknowledgement",
			response: func(t *testing.T) fakeResponse {
				return fakeResponse{status: 200, contentType: "text/xml;charset=UTF-8", body: staticBody(signedAck(t))}
			},
			answersThisUUID: func(t *testing.T) string { return requestUUID(signedAck(t)) },
			check: func(t *testing.T, r sendResult) {
				if r.err != nil {
					t.Fatal(r.err)
				}
				if r.req.Method != http.MethodPost || r.req.Header.Get("Content-Type") != contentTypeSOAP || r.req.Header.Get("SOAPAction") != `"`+SOAPAction+`"` {
					t.Errorf("request %s %v", r.req.Method, r.req.Header)
				}
				if !bytes.Equal(r.body, r.msg.XML) {
					t.Error("request body differs from the prepared message")
				}
				resp := r.resp
				if !resp.Accepted() || len(resp.POK) != 39 || !strings.HasSuffix(resp.POK, "-ff") || !resp.Test || !resp.Signed {
					t.Errorf("response %+v", resp)
				}
				if resp.ReceivedAt.IsZero() || resp.TransactionID != fakeTransaction || len(resp.Warnings) != 0 || resp.Raw == nil {
					t.Errorf("response %+v", resp)
				}
				if CheckResponseSignerOrganization(resp.SigningCertificate) != nil {
					t.Errorf("signer %v", resp.SigningCertificate.Subject)
				}
			},
		},
		{
			name: "acknowledgement with warnings",
			response: func(t *testing.T) fakeResponse {
				return fakeResponse{status: 200, contentType: "text/xml", body: staticBody(fixtures.PlaygroundResponse(fixtures.ResponseWarnings))}
			},
			answersThisUUID: func(t *testing.T) string { return requestUUID(fixtures.PlaygroundResponse(fixtures.ResponseWarnings)) },
			check: func(t *testing.T, r sendResult) {
				if r.err != nil {
					t.Fatal(r.err)
				}
				want := []Warning{
					{WarningEICMismatch, "EIC poplatnika v datove zprave se neshoduje s EIC v certifikatu"},
					{WarningUnitIDFormat, "id_jednotky neodpovida formatem pridelenemu c. evidencni jednotky"},
					{WarningDelegatingEICIsOwner, "EIC poverujiciho se shoduje s EIC poplatnika"},
				}
				if len(r.resp.Warnings) != len(want) {
					t.Fatalf("warnings %+v", r.resp.Warnings)
				}
				for i := range want {
					if r.resp.Warnings[i] != want[i] {
						t.Errorf("warning %d = %+v, want %+v", i, r.resp.Warnings[i], want[i])
					}
				}
			},
		},
		{
			name: "tampered acknowledgement",
			response: func(t *testing.T) fakeResponse {
				tampered := pokFirstDigitPattern.ReplaceAllFunc(signedAck(t), func(m []byte) []byte {
					if m[len(m)-1] == '0' {
						return []byte(`pok="1`)
					}
					return []byte(`pok="0`)
				})
				return fakeResponse{status: 200, contentType: "text/xml", body: staticBody(tampered)}
			},
			answersThisUUID: func(t *testing.T) string { return requestUUID(signedAck(t)) },
			check: func(t *testing.T, r sendResult) {
				if !errors.Is(r.err, ErrInvalidSignature) || r.resp == nil || r.resp.Signed {
					t.Fatalf("resp=%+v err=%v", r.resp, r.err)
				}
			},
		},
		{
			name: "signer certificate rejected by custom check",
			response: func(t *testing.T) fakeResponse {
				return fakeResponse{status: 200, contentType: "text/xml", body: staticBody(signedAck(t))}
			},
			opts:            []Option{WithResponseCertificateCheck(func(*x509.Certificate) error { return errors.New("untrusted") })},
			answersThisUUID: func(t *testing.T) string { return requestUUID(signedAck(t)) },
			check: func(t *testing.T, r sendResult) {
				if !errors.Is(r.err, ErrInvalidSignature) || !strings.Contains(r.err.Error(), "untrusted") {
					t.Fatalf("err = %v", r.err)
				}
			},
		},
		{
			name: "signer organization option accepts the expected signer",
			response: func(t *testing.T) fakeResponse {
				return fakeResponse{status: 200, contentType: "text/xml", body: staticBody(signedAck(t))}
			},
			opts:            []Option{WithResponseSignerOrganization(ResponseSignerOrganization)},
			answersThisUUID: func(t *testing.T) string { return requestUUID(signedAck(t)) },
			check: func(t *testing.T, r sendResult) {
				if r.err != nil || !r.resp.Signed {
					t.Fatalf("resp=%+v err=%v", r.resp, r.err)
				}
			},
		},
		{
			name: "signer organization option rejects another signer",
			response: func(t *testing.T) fakeResponse {
				return fakeResponse{status: 200, contentType: "text/xml", body: staticBody(signedAck(t))}
			},
			opts:            []Option{WithResponseSignerOrganization("Another organization")},
			answersThisUUID: func(t *testing.T) string { return requestUUID(signedAck(t)) },
			check: func(t *testing.T, r sendResult) {
				if !errors.Is(r.err, ErrInvalidSignature) {
					t.Fatalf("err = %v", r.err)
				}
			},
		},
		{
			name: "signer chain not trusted",
			response: func(t *testing.T) fakeResponse {
				return fakeResponse{status: 200, contentType: "text/xml", body: staticBody(signedAck(t))}
			},
			opts:            []Option{WithResponseTrust(ResponseTrust{Roots: x509.NewCertPool()})},
			answersThisUUID: func(t *testing.T) string { return requestUUID(signedAck(t)) },
			check: func(t *testing.T, r sendResult) {
				if !errors.Is(r.err, ErrInvalidSignature) {
					t.Fatalf("err = %v", r.err)
				}
			},
		},
		{
			name: "acknowledgement of another message",
			response: func(t *testing.T) fakeResponse {
				return fakeResponse{status: 200, contentType: "text/xml", body: staticBody(signedAck(t))}
			},
			check: func(t *testing.T, r sendResult) {
				if !errors.Is(r.err, ErrResponseUUIDMismatch) {
					t.Fatalf("err = %v", r.err)
				}
			},
		},
		{
			name: "unsigned acknowledgement",
			response: func(*testing.T) fakeResponse {
				return fakeResponse{status: 200, contentType: "text/xml", body: unsignedOdpoved(`<eet:Odpoved><eet:Hlavicka uuid_zpravy="{uuid}" dat_prij="2027-03-04T18:25:21+01:00"/><eet:Potvrzeni pok="987a6be5-6af5-44f3-b4fc-987654321000-02"/></eet:Odpoved>`)}
			},
			check: func(t *testing.T, r sendResult) {
				if !errors.Is(r.err, ErrResponseNotSigned) || r.resp == nil || r.resp.POK != "987a6be5-6af5-44f3-b4fc-987654321000-02" {
					t.Fatalf("resp=%+v err=%v", r.resp, r.err)
				}
			},
		},
		{
			name: "unsigned acknowledgement without signature verification",
			response: func(*testing.T) fakeResponse {
				return fakeResponse{status: 200, contentType: "text/xml", body: unsignedOdpoved(`<eet:Odpoved><eet:Hlavicka uuid_zpravy="{uuid}" dat_prij="2027-03-04T18:25:21+01:00"/><eet:Potvrzeni pok="987a6be5-6af5-44f3-b4fc-987654321000-02"/></eet:Odpoved>`)}
			},
			opts: []Option{WithoutResponseSignatureVerification()},
			check: func(t *testing.T, r sendResult) {
				if r.err != nil || !r.resp.Accepted() || r.resp.Signed || r.resp.Test {
					t.Fatalf("resp=%+v err=%v", r.resp, r.err)
				}
			},
		},
		{
			name: "rejected message",
			response: func(t *testing.T) fakeResponse {
				return fakeResponse{status: 200, contentType: "text/xml", body: staticBody(fixtures.PlaygroundResponse(fixtures.ResponseError))}
			},
			check: func(t *testing.T, r sendResult) {
				re, ok := errors.AsType[*ResponseError](r.err)
				if !ok || re.Code != CodeInvalidXMLEncoding || re.Message != "Kodovani XML neni platne" || re.Temporary() || !re.Test || re.TransactionID != fakeTransaction || re.RejectedAt.IsZero() {
					t.Fatalf("err = %#v", r.err)
				}
				if r.resp == nil || r.resp.Accepted() || r.resp.Error != re {
					t.Fatalf("resp = %+v", r.resp)
				}
			},
		},
		{
			name: "temporary technical error",
			response: func(*testing.T) fakeResponse {
				return fakeResponse{status: 200, contentType: "text/xml", body: unsignedOdpoved(`<eet:Odpoved><eet:Hlavicka dat_odmit="2027-03-04T18:25:21+01:00"/><eet:Chyba kod="-1">
              Docasna technicka chyba zpracovani – odeslete prosim
              datovou zpravu pozdeji
      </eet:Chyba></eet:Odpoved>`)}
			},
			check: func(t *testing.T, r sendResult) {
				re, ok := errors.AsType[*ResponseError](r.err)
				if !ok || !re.Temporary() || re.Message != "Docasna technicka chyba zpracovani – odeslete prosim datovou zpravu pozdeji" {
					t.Fatalf("err = %#v", r.err)
				}
			},
		},
		{
			name: "verification result",
			response: func(t *testing.T) fakeResponse {
				return fakeResponse{status: 200, contentType: "text/xml", body: staticBody(fixtures.PlaygroundResponse(fixtures.ResponseVerify))}
			},
			sendOpts:        SendOptions{Verification: true},
			answersThisUUID: func(t *testing.T) string { return requestUUID(fixtures.PlaygroundResponse(fixtures.ResponseVerify)) },
			check: func(t *testing.T, r sendResult) {
				if r.err != nil || !r.resp.VerificationSucceeded() || r.resp.Accepted() || r.resp.Signed || !r.resp.Test {
					t.Fatalf("resp=%+v err=%v", r.resp, r.err)
				}
			},
		},
		{
			name: "verification result outside verification mode",
			response: func(t *testing.T) fakeResponse {
				return fakeResponse{status: 200, contentType: "text/xml", body: staticBody(fixtures.PlaygroundResponse(fixtures.ResponseVerify))}
			},
			answersThisUUID: func(t *testing.T) string { return requestUUID(fixtures.PlaygroundResponse(fixtures.ResponseVerify)) },
			check: func(t *testing.T, r sendResult) {
				if re, ok := errors.AsType[*ResponseError](r.err); !ok || re.Code != CodeVerificationOK {
					t.Fatalf("err = %v", r.err)
				}
			},
		},
		{
			name: "SOAP fault",
			response: func(*testing.T) fakeResponse {
				return fakeResponse{status: 500, contentType: "text/xml", body: unsignedOdpoved(`<soapenv:Fault><faultcode>soapenv:Client</faultcode><faultstring>Rejected</faultstring></soapenv:Fault>`)}
			},
			check: func(t *testing.T, r sendResult) {
				f, ok := errors.AsType[*SOAPFault](r.err)
				if !ok || f.Code != "soapenv:Client" || f.String != "Rejected" || f.HTTPStatus != 500 || f.TransactionID != fakeTransaction || f.MessageUUID != r.msg.UUID {
					t.Fatalf("err = %#v", r.err)
				}
			},
		},
		{
			name: "HTML error page",
			response: func(*testing.T) fakeResponse {
				return fakeResponse{status: 503, contentType: "text/html", body: staticBody([]byte("<html>down</html>"))}
			},
			check: func(t *testing.T, r sendResult) {
				h, ok := errors.AsType[*HTTPError](r.err)
				if !ok || h.StatusCode != 503 || h.Body != "<html>down</html>" || h.TransactionID != fakeTransaction || h.MessageUUID != r.msg.UUID {
					t.Fatalf("err = %#v", r.err)
				}
			},
		},
		{
			name: "malformed XML",
			response: func(*testing.T) fakeResponse {
				return fakeResponse{status: 200, contentType: "text/xml", body: staticBody([]byte("<soapenv:Envelope"))}
			},
			check: func(t *testing.T, r sendResult) {
				if !errors.Is(r.err, ErrInvalidResponse) {
					t.Fatalf("err = %v", r.err)
				}
			},
		},
		{
			name: "response time limit exceeded",
			response: func(t *testing.T) fakeResponse {
				return fakeResponse{status: 200, contentType: "text/xml", body: staticBody(signedAck(t)), delay: 2 * MinTimeout}
			},
			opts: []Option{WithTimeout(MinTimeout)},
			check: func(t *testing.T, r sendResult) {
				te, ok := errors.AsType[*TransportError](r.err)
				if !ok || !te.Timeout || te.MessageUUID != r.msg.UUID {
					t.Fatalf("err = %#v", r.err)
				}
			},
		},
		{
			name: "same message sent twice",
			response: func(t *testing.T) fakeResponse {
				return fakeResponse{status: 200, contentType: "text/xml", body: staticBody(signedAck(t))}
			},
			answersThisUUID: func(t *testing.T) string { return requestUUID(signedAck(t)) },
			check: func(t *testing.T, r sendResult) {
				if r.err != nil {
					t.Fatal(r.err)
				}
				if _, err := r.msg.Send(context.Background()); !errors.Is(err, ErrMessageAlreadySent) {
					t.Fatalf("err = %v", err)
				}
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			fake := newFakeEET(t, tc.response(t))
			msg, err := newTestClient(t, fake.srv.URL, tc.opts...).Prepare(testSale(), tc.sendOpts)
			if err != nil {
				t.Fatal(err)
			}
			if tc.answersThisUUID != nil {
				msg.UUID = tc.answersThisUUID(t)
			}
			resp, err := msg.Send(context.Background())
			req, body := fake.lastRequest(t)
			tc.check(t, sendResult{msg: msg, resp: resp, err: err, req: req, body: body})
		})
	}
}

func TestClientSend(t *testing.T) {
	t.Parallel()
	accepted := `<eet:Odpoved><eet:Hlavicka uuid_zpravy="{uuid}" dat_prij="2027-03-04T18:25:21+01:00"/><eet:Potvrzeni pok="987a6be5-6af5-44f3-b4fc-987654321000-ff" test="true"/></eet:Odpoved>`
	verified := `<eet:Odpoved><eet:Hlavicka uuid_zpravy="{uuid}" dat_odmit="2027-03-04T18:25:21+01:00"/><eet:Chyba kod="0" test="true">Datovou zpravu evidovane trzby v overovacim modu se podarilo zpracovat</eet:Chyba></eet:Odpoved>`
	for _, tc := range []struct {
		name     string
		odpoved  string
		send     func(*Client, context.Context, Sale) (*Response, error)
		want     []string
		absent   string
		accepted bool
	}{
		{name: "Send", odpoved: accepted, send: (*Client).Send, want: []string{`prvni_zaslani="true"`}, absent: "overeni", accepted: true},
		{name: "Resend", odpoved: accepted, send: (*Client).Resend, want: []string{`prvni_zaslani="false"`}, absent: "overeni", accepted: true},
		{name: "Verify", odpoved: verified, send: (*Client).Verify, want: []string{`prvni_zaslani="true"`, `overeni="true"`}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			fake := newFakeEET(t, fakeResponse{status: 200, contentType: "text/xml", body: unsignedOdpoved(tc.odpoved)})
			c := newTestClient(t, fake.srv.URL, WithoutResponseSignatureVerification())
			resp, err := tc.send(c, context.Background(), testSale())
			if err != nil {
				t.Fatal(err)
			}
			if resp.Accepted() != tc.accepted || resp.VerificationSucceeded() == tc.accepted {
				t.Fatalf("response %+v", resp)
			}
			_, body := fake.lastRequest(t)
			for _, w := range tc.want {
				if !bytes.Contains(body, []byte(w)) {
					t.Errorf("request lacks %s", w)
				}
			}
			if tc.absent != "" && bytes.Contains(body, []byte(tc.absent)) {
				t.Errorf("request must not carry %s", tc.absent)
			}
		})
	}
}

func TestClientLint(t *testing.T) {
	t.Parallel()
	c := newTestClient(t, Playground.URL)
	for _, tc := range []struct {
		name   string
		mutate func(Sale) Sale
		want   []WarningCode
	}{
		{name: "clean", mutate: func(s Sale) Sale { s.UnitID = 24; return s }},
		{name: "EIC differs from the client certificate", mutate: func(s Sale) Sale { s.EIC, s.UnitID = "CZ683555118", 24; return s }, want: []WarningCode{WarningEICMismatch}},
		{name: "unit identifier format", mutate: func(s Sale) Sale { s.UnitID = 5; return s }, want: []WarningCode{WarningUnitIDFormat}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var got []WarningCode
			for _, w := range c.Lint(tc.mutate(testSale())) {
				got = append(got, w.Code)
			}
			if !slices.Equal(got, tc.want) {
				t.Fatalf("warnings = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestClientForSigner(t *testing.T) {
	t.Parallel()
	fake := newFakeEET(t, fakeResponse{status: 200, contentType: "text/xml", body: unsignedOdpoved(`<eet:Odpoved><eet:Hlavicka uuid_zpravy="{uuid}"/><eet:Potvrzeni pok="987a6be5-6af5-44f3-b4fc-987654321000-ff" test="true"/></eet:Odpoved>`)})
	base := newTestClient(t, fake.srv.URL, WithoutResponseSignatureVerification(), WithTimeout(MinTimeout+time.Second))
	for _, tc := range []struct {
		name    string
		signer  func(*testing.T) *Signer
		wantErr bool
	}{
		{name: "another taxpayer", signer: func(t *testing.T) *Signer { return playgroundSigner(t, "CZ683555118") }},
		{name: "missing signer", signer: func(*testing.T) *Signer { return nil }, wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			c, err := base.ForSigner(tc.signer(t))
			if (err != nil) != tc.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tc.wantErr)
			}
			if tc.wantErr {
				return
			}
			if base.Signer().EIC() != testEIC || c.Signer().EIC() != "CZ683555118" || c.Environment() != base.Environment() || c.http != base.http || c.timeout != base.timeout || c.verify != base.verify {
				t.Fatal("ForSigner must share configuration and keep the original signer")
			}
			sale := testSale()
			sale.EIC = "CZ683555118"
			if _, err := c.Send(context.Background(), sale); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestClientSetSigner(t *testing.T) {
	t.Parallel()
	c := newTestClient(t, Playground.URL)
	c.SetSigner(playgroundSigner(t, "CZ683555118"))
	msg, err := c.Prepare(testSale(), SendOptions{})
	if err != nil {
		t.Fatal(err)
	}
	v, err := wssec.Verify(msg.XML)
	if err != nil {
		t.Fatal(err)
	}
	if v.Certificate.Subject.CommonName != "CZ683555118" {
		t.Fatalf("signed by %s", v.Certificate.Subject.CommonName)
	}
}
