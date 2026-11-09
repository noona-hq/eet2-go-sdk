package caeet

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/noona-hq/eet2-go-sdk/eet"
	"github.com/noona-hq/eet2-go-sdk/internal/fixtures"
)

const (
	testReqID        = "3fa85f64-5717-4562-b3fc-2c963f66afa6"
	testSerial       = "24961511666821687692"
	issuedAfterPolls = 3
)

func testSigner(t *testing.T) *eet.Signer {
	t.Helper()
	s, err := eet.LoadPKCS12(fixtures.PlaygroundP12(fixtures.EICLegalEntity), fixtures.PlaygroundPassword())
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func checkToken(s *eet.Signer, token string) error {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return fmt.Errorf("token %q is not JWS compact serialization", token)
	}
	var segments [3][]byte
	for i, p := range parts {
		b, err := base64.RawURLEncoding.DecodeString(p)
		if err != nil {
			return fmt.Errorf("segment %d: %w", i, err)
		}
		segments[i] = b
	}
	var h map[string]string
	if err := json.Unmarshal(segments[0], &h); err != nil {
		return err
	}
	var claims tokenClaims
	if err := json.Unmarshal(segments[1], &claims); err != nil {
		return err
	}
	thumb := sha256.Sum256(s.Certificate().Raw)
	if h["alg"] != "RS256" || h["typ"] != "JWT" || h["x5t#S256"] != base64.RawURLEncoding.EncodeToString(thumb[:]) || h["x5c"] != "" {
		return fmt.Errorf("header %v", h)
	}
	if lifetime := claims.ExpiresAt - claims.IssuedAt; lifetime <= 0 || lifetime > int64(MaxTokenLifetime/time.Second) {
		return fmt.Errorf("claims %+v", claims)
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	return rsa.VerifyPKCS1v15(s.Certificate().PublicKey.(*rsa.PublicKey), crypto.SHA256, digest[:], segments[2])
}

type fakeCA struct {
	t        *testing.T
	signer   *eet.Signer
	p12      []byte
	password string
	pending  []string
	rejected bool
	mu       sync.Mutex
	polls    int
	stored   bool
	acked    bool
	calls    []string
}

func (f *fakeCA) write(w http.ResponseWriter, status int, body string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if _, err := w.Write([]byte(body)); err != nil {
		f.t.Error(err)
	}
}

func (f *fakeCA) writeJSON(w http.ResponseWriter, v any) {
	data, err := json.Marshal(v)
	if err != nil {
		f.t.Error(err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	f.write(w, http.StatusOK, string(data))
}

func (f *fakeCA) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	route := r.Method + " " + r.URL.Path
	f.calls = append(f.calls, route)
	token, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok {
		f.write(w, http.StatusUnauthorized, `{"code":2,"message":"Unauthorized access."}`)
		return
	}
	if err := checkToken(f.signer, token); err != nil {
		f.t.Errorf("invalid token: %v", err)
		f.write(w, http.StatusUnauthorized, `{"code":2,"message":"Unauthorized access."}`)
		return
	}
	switch route {
	case "GET /api/request/not-finished":
		f.writeJSON(w, map[string]any{"count": len(f.pending), "data": f.pending})
	case "POST /api/request/renew":
		f.write(w, http.StatusCreated, `{"reqId":"`+testReqID+`"}`)
	case "GET /api/request/" + testReqID + "/status":
		f.polls++
		switch {
		case f.rejected:
			f.write(w, http.StatusOK, `{"reqId":"`+testReqID+`","state":"REJECTED","rejectedReason":"Selhání kontroly parametrů žádosti"}`)
		case f.polls < issuedAfterPolls:
			w.Header().Set(retryAfterHeader, "1")
			f.write(w, http.StatusOK, `{"reqId":"`+testReqID+`","state":"INPROCESS","pollAfterSeconds":1}`)
		default:
			f.write(w, http.StatusOK, `{"reqId":"`+testReqID+`","state":"ISSUED"}`)
		}
	case "POST /api/request/" + testReqID + "/claim-download":
		f.writeJSON(w, map[string]any{
			"pkcs12":   f.p12,
			"password": f.password,
			"certificate": map[string]any{
				"sn":        testSerial,
				"validFrom": "2026-01-04 11:13:33+00:00",
				"validTo":   "2027-01-04T11:13:33+00:00",
				"state":     "VALID",
			},
		})
	case "POST /api/request/" + testReqID + "/ack-download":
		if !f.stored {
			f.t.Error("ack-download called before the bundle was stored")
		}
		f.acked = true
		w.WriteHeader(http.StatusNoContent)
	default:
		f.write(w, http.StatusNotFound, `{"code":4,"message":"Unknown object.","additionalInfo":"`+r.URL.Path+`"}`)
	}
}

func newFakeCA(t *testing.T, setup func(*fakeCA)) (*fakeCA, *Client) {
	t.Helper()
	s := testSigner(t)
	f := &fakeCA{t: t, signer: s, p12: fixtures.PlaygroundP12(fixtures.EICLegalEntity), password: fixtures.PlaygroundPassword()}
	setup(f)
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	c, err := New(Environment{Name: "fake", BaseURL: srv.URL + "/api"}, s)
	if err != nil {
		t.Fatal(err)
	}
	return f, c
}

func TestRenewCertificate(t *testing.T) {
	t.Parallel()
	statusCall := "GET /api/request/" + testReqID + "/status"
	for _, tc := range []struct {
		name      string
		setup     func(*fakeCA)
		storeErr  error
		wantErr   error
		wantCalls []string
		wantAcked bool
	}{
		{
			name:  "new request",
			setup: func(*fakeCA) {},
			wantCalls: []string{
				"GET /api/request/not-finished",
				"POST /api/request/renew",
				statusCall, statusCall, statusCall,
				"POST /api/request/" + testReqID + "/claim-download",
				"POST /api/request/" + testReqID + "/ack-download",
			},
			wantAcked: true,
		},
		{
			name:  "resumes pending request",
			setup: func(f *fakeCA) { f.pending, f.polls = []string{testReqID}, issuedAfterPolls },
			wantCalls: []string{
				"GET /api/request/not-finished",
				statusCall,
				"POST /api/request/" + testReqID + "/claim-download",
				"POST /api/request/" + testReqID + "/ack-download",
			},
			wantAcked: true,
		},
		{
			name:     "store failure keeps the download open",
			setup:    func(f *fakeCA) { f.polls = issuedAfterPolls },
			storeErr: errors.New("vault down"),
			wantErr:  errors.New("caeet: storing renewed certificate: vault down"),
			wantCalls: []string{
				"GET /api/request/not-finished",
				"POST /api/request/renew",
				statusCall,
				"POST /api/request/" + testReqID + "/claim-download",
			},
		},
		{
			name:    "rejected request",
			setup:   func(f *fakeCA) { f.rejected = true },
			wantErr: ErrRejected,
			wantCalls: []string{
				"GET /api/request/not-finished",
				"POST /api/request/renew",
				statusCall,
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			f, c := newFakeCA(t, tc.setup)
			bundle, err := c.RenewCertificate(context.Background(), func(*Bundle) error {
				f.mu.Lock()
				defer f.mu.Unlock()
				f.stored = tc.storeErr == nil
				return tc.storeErr
			})
			switch {
			case tc.wantErr == nil && err != nil:
				t.Fatal(err)
			case tc.wantErr != nil && !errors.Is(err, tc.wantErr) && (err == nil || err.Error() != tc.wantErr.Error()):
				t.Fatalf("err = %v, want %v", err, tc.wantErr)
			}
			f.mu.Lock()
			defer f.mu.Unlock()
			if !slices.Equal(f.calls, tc.wantCalls) || f.acked != tc.wantAcked {
				t.Fatalf("acked=%v calls:\n%s", f.acked, strings.Join(f.calls, "\n"))
			}
			if tc.wantErr != nil {
				return
			}
			want := Certificate{
				SerialNumber: testSerial,
				ValidFrom:    time.Date(2026, 1, 4, 11, 13, 33, 0, time.UTC),
				ValidTo:      time.Date(2027, 1, 4, 11, 13, 33, 0, time.UTC),
				State:        CertificateValid,
			}
			got := bundle.Certificate
			if got.SerialNumber != want.SerialNumber || !got.ValidFrom.Equal(want.ValidFrom) || !got.ValidTo.Equal(want.ValidTo) || got.State != want.State {
				t.Fatalf("certificate %+v, want %+v", got, want)
			}
			s, err := bundle.Signer()
			if err != nil || s.EIC() != fixtures.EICLegalEntity {
				t.Fatalf("signer %v, err %v", s, err)
			}
		})
	}
}

func TestStatus(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name      string
		reqID     string
		polls     int
		wantState State
		wantPoll  time.Duration
		wantErr   func(error) bool
	}{
		{name: "in process", reqID: testReqID, wantState: StateInProcess, wantPoll: time.Second},
		{name: "issued", reqID: testReqID, polls: issuedAfterPolls, wantState: StateIssued},
		{name: "unknown request", reqID: "00000000-0000-0000-0000-000000000000", wantErr: func(err error) bool {
			e, ok := errors.AsType[*APIError](err)
			return ok && e.StatusCode == http.StatusNotFound && e.Code == 4 && e.Message == "Unknown object."
		}},
		{name: "malformed request id", reqID: "../renew", wantErr: func(err error) bool {
			return err != nil && strings.Contains(err.Error(), "invalid request id")
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, c := newFakeCA(t, func(f *fakeCA) { f.polls = tc.polls })
			st, err := c.Status(context.Background(), tc.reqID)
			if tc.wantErr != nil {
				if !tc.wantErr(err) {
					t.Fatalf("err = %#v", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if st.RequestID != testReqID || st.State != tc.wantState || st.PollAfter != tc.wantPoll {
				t.Fatalf("status %+v", st)
			}
		})
	}
}

func TestToken(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name     string
		lifetime time.Duration
		wantErr  bool
	}{
		{name: "default lifetime"},
		{name: "maximum lifetime", lifetime: MaxTokenLifetime},
		{name: "longer than allowed", lifetime: MaxTokenLifetime + time.Second, wantErr: true},
		{name: "negative lifetime", lifetime: -time.Second, wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			s := testSigner(t)
			var opts []Option
			if tc.lifetime != 0 {
				opts = append(opts, WithTokenLifetime(tc.lifetime))
			}
			c, err := New(Test, s, opts...)
			if (err != nil) != tc.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tc.wantErr)
			}
			if tc.wantErr {
				return
			}
			token, err := c.Token()
			if err != nil {
				t.Fatal(err)
			}
			if err := checkToken(s, token); err != nil {
				t.Fatal(err)
			}
		})
	}
}
