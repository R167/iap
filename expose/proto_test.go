package expose

import (
	"bufio"
	jsonv1 "encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
)

// The control stream and refusal bodies are shared with the iap-tunnel
// server, which may encode and decode with encoding/json (v1) or v2. The
// lines below are literal v1 output for the same messages.

func TestControlMarshalLineMatchesV1(t *testing.T) {
	full := Control{Type: TypeRefused, URL: "https://x.example.com/?a=1&b=<2>", MaxAgeSeconds: 3600, ReserveSeconds: 60,
		TookFrom: "r1", Reason: ReasonTaken, By: "r2", Error: CodeNameTaken, Message: "m", Holder: "h"}
	for c, want := range map[Control]string{
		{Type: TypeReady, URL: "https://x.example.com/?a=1&b=2", MaxAgeSeconds: 3600}: `{"type":"ready","url":"https://x.example.com/?a=1\u0026b=2","max_age_seconds":3600}`,
		{Type: TypeReady}: `{"type":"ready"}`,
		{Type: TypeClosing, Reason: ReasonTaken, By: "r2"}: `{"type":"closing","reason":"taken","by":"r2"}`,
		full: `{"type":"refused","url":"https://x.example.com/?a=1\u0026b=\u003c2\u003e","max_age_seconds":3600,"reserve_seconds":60,"took_from":"r1","reason":"taken","by":"r2","error":"name_taken","message":"m","holder":"h"}`,
	} {
		if got := string(c.MarshalLine()); got != want+"\n" {
			t.Errorf("MarshalLine:\n got %s want %s", got, want)
		}
		// A v1 peer reads it back unchanged.
		var back Control
		if err := jsonv1.Unmarshal(c.MarshalLine(), &back); err != nil || back != c {
			t.Errorf("v1 decode of %s: %+v %v", want, back, err)
		}
	}
}

// readControl accepts whatever a v1 encoder wrote or a v1 decoder accepted:
// unknown members, null, names in another case, a repeated name (last wins),
// invalid UTF-8 (U+FFFD), and v1's escapes.
func TestReadControlV1Input(t *testing.T) {
	in := strings.Join([]string{
		`{"type":"ready","url":"https://x.example.com/?a=1\u0026b=2","max_age_seconds":3600,"future":{"x":[1,null]}}`,
		`{"type":"closing","reason":null,"by":"r2","max_age_seconds":null}`,
		`{"Type":"closing","REASON":"taken","Took_From":"r1"}`,
		`{"type":"ready","type":"closing"}`,
		"{\"type\":\"refused\",\"message\":\"bad\xffbyte\"}",
	}, "\n") + "\n"
	want := []Control{
		{Type: TypeReady, URL: "https://x.example.com/?a=1&b=2", MaxAgeSeconds: 3600},
		{Type: TypeClosing, By: "r2"},
		{Type: TypeClosing, Reason: ReasonTaken, TookFrom: "r1"},
		{Type: TypeClosing},
		{Type: TypeRefused, Message: "bad\uFFFDbyte"},
	}
	br := bufio.NewReader(strings.NewReader(in))
	for i, w := range want {
		var m Control
		if err := readControl(br, &m); err != nil || m != w {
			t.Errorf("line %d: %+v %v, want %+v", i, m, err, w)
		}
	}
	var m Control
	if err := readControl(br, &m); !errors.Is(err, io.EOF) {
		t.Errorf("after the last line: %v", err)
	}
}

// A refusal body decodes as v1's Decoder.Decode did: the first value only,
// with v1's leniency.
func TestRefusalFromV1Body(t *testing.T) {
	resp := func(status int, body string) *http.Response {
		return &http.Response{StatusCode: status, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(body))}
	}
	err := refusalFrom(resp(409, `{"error":"name_taken","message":"held","holder":"r1","extra":[1]}`+"\ntrailing junk"), "tunnel.example.com")
	var r *Refusal
	if !errors.As(err, &r) || *r != (Refusal{Code: CodeNameTaken, Message: "held", Holder: "r1"}) {
		t.Errorf("refusal: %#v", err)
	}
	err = refusalFrom(resp(409, `{"Error":"quota_exceeded","message":"a","message":"b","holder":null}`), "tunnel.example.com")
	if !errors.As(err, &r) || *r != (Refusal{Code: CodeQuota, Message: "b"}) {
		t.Errorf("lenient refusal: %#v", err)
	}
	err = refusalFrom(resp(403, `{"error":"forbidden","principal":"agent:user:alice@example.com:box:cli:s1"}`), "tunnel.example.com")
	var pe *ProxyRefusedError
	if !errors.As(err, &pe) || pe.Code != "forbidden" || pe.Principal != "agent:user:alice@example.com:box:cli:s1" {
		t.Errorf("proxy refusal: %#v", err)
	}
	if err := refusalFrom(resp(502, "<html>bad gateway</html>"), "tunnel.example.com"); err == nil || err.Error() != "tunnel endpoint: HTTP 502 " {
		t.Errorf("non-JSON: %v", err)
	}
}
