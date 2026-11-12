package expose

import (
	"bufio"
	"bytes"
	jsonv1 "encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
)

// The control stream and refusal bodies are shared with the iap-tunnel
// server, which may encode and decode with encoding/json (v1) or v2. The
// lines below are literal v1 output.

// A v1 peer reads what MarshalLine writes.
func TestControlMarshalLineV1Decode(t *testing.T) {
	full := Control{Type: TypeRefused, URL: "https://x.example.com/?a=1&b=<2>", MaxAgeSeconds: 3600, ReserveSeconds: 60,
		TookFrom: "r1", Reason: ReasonTaken, By: "r2", Error: CodeNameTaken, Message: "m", Holder: "h"}
	for _, c := range []Control{full, {Type: TypeReady, URL: "https://x.example.com/", MaxAgeSeconds: 3600}, {Type: TypeClosing, Reason: ReasonTaken, By: "r2"}} {
		line := c.MarshalLine()
		if !bytes.HasSuffix(line, []byte("}\n")) || bytes.Count(line, []byte("\n")) != 1 {
			t.Errorf("MarshalLine = %q, want one line", line)
		}
		var back Control
		if err := jsonv1.Unmarshal(line, &back); err != nil || back != c {
			t.Errorf("v1 decode of %s: %+v %v", line, back, err)
		}
	}
	// Zero numbers are omitted, as v1's omitempty did.
	if got := string(Control{Type: TypeReady}.MarshalLine()); got != `{"type":"ready"}`+"\n" {
		t.Errorf("MarshalLine = %s", got)
	}
}

// readControl reads the lines a v1 server writes: v1's escapes, unknown
// members, and null.
func TestReadControlV1Input(t *testing.T) {
	in := strings.Join([]string{
		`{"type":"ready","url":"https://x.example.com/?a=1\u0026b=\u003c2\u003e","max_age_seconds":3600,"future":{"x":[1,null]}}`,
		`{"type":"closing","reason":null,"by":"r2","max_age_seconds":null}`,
		`{"type":"refused","error":"name_taken","message":"held","holder":"r1"}`,
	}, "\n") + "\n"
	want := []Control{
		{Type: TypeReady, URL: "https://x.example.com/?a=1&b=<2>", MaxAgeSeconds: 3600},
		{Type: TypeClosing, By: "r2"},
		{Type: TypeRefused, Error: CodeNameTaken, Message: "held", Holder: "r1"},
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

// A refusal body decodes from its first value: unknown members, null and
// trailing bytes are fine.
func TestRefusalFromV1Body(t *testing.T) {
	resp := func(status int, body string) *http.Response {
		return &http.Response{StatusCode: status, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(body))}
	}
	err := refusalFrom(resp(409, `{"error":"name_taken","message":"held","holder":null,"extra":[1]}`+"\ntrailing junk"), "tunnel.example.com")
	var r *Refusal
	if !errors.As(err, &r) || *r != (Refusal{Code: CodeNameTaken, Message: "held"}) {
		t.Errorf("refusal: %#v", err)
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
