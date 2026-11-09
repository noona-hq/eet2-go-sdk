package eet

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"sync"
	"testing"
	"time"
)

type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) record(t *testing.T) map[string]any {
	t.Helper()
	b.mu.Lock()
	defer b.mu.Unlock()
	var rec map[string]any
	if err := json.Unmarshal(b.buf.Bytes(), &rec); err != nil {
		t.Fatalf("log %q: %v", b.buf.String(), err)
	}
	return rec
}

func TestWithLogger(t *testing.T) {
	t.Parallel()
	accepted := `<eet:Odpoved><eet:Hlavicka uuid_zpravy="{uuid}" dat_prij="2027-03-04T18:25:21+01:00"/><eet:Potvrzeni pok="987a6be5-6af5-44f3-b4fc-987654321000-ff" test="true"/></eet:Odpoved>`
	for _, tc := range []struct {
		name      string
		response  fakeResponse
		wantLevel string
		want      map[string]any
	}{
		{
			name:      "accepted",
			response:  fakeResponse{status: 200, contentType: "text/xml", body: unsignedOdpoved(accepted)},
			wantLevel: "INFO",
			want:      map[string]any{"pok": "987a6be5-6af5-44f3-b4fc-987654321000-ff", "transaction_id": fakeTransaction, "first_sending": true},
		},
		{
			name:      "unavailable",
			response:  fakeResponse{status: 503, contentType: "text/html", body: staticBody([]byte("<html/>"))},
			wantLevel: "WARN",
			want:      map[string]any{"error": "eet: unexpected HTTP status 503", "should_resend": true},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var buf syncBuffer
			logger := slog.New(slog.NewJSONHandler(&buf, nil))
			fake := newFakeEET(t, tc.response)
			c := newTestClient(t, fake.srv.URL, WithoutResponseSignatureVerification(), WithLogger(logger))
			msg, err := c.Prepare(testSale(), SendOptions{})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := msg.Send(context.Background()); err != nil && tc.wantLevel == "INFO" {
				t.Fatal(err)
			}
			rec := buf.record(t)
			if rec["level"] != tc.wantLevel || rec["msg"] != logMessage || rec["uuid"] != msg.UUID || rec["eic"] != testEIC || rec["register_id"] != "SDK-TEST" {
				t.Fatalf("log record %v", rec)
			}
			if d, ok := rec["duration"].(float64); !ok || time.Duration(d) <= 0 {
				t.Fatalf("duration %v", rec["duration"])
			}
			for k, v := range tc.want {
				if rec[k] != v {
					t.Errorf("%s = %v, want %v", k, rec[k], v)
				}
			}
		})
	}
}
