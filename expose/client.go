// Package expose is the client side of `iap expose`: it publishes a local
// HTTP server (127.0.0.1:<port>) at https://<name>.<domain> through a tunnel
// service behind an iap-authz proxy (the iap-tunnel server, which is not part
// of this module and imports this package's wire protocol).
//
// The client dials the tunnel endpoint with an ordinary agent token for that
// host (iapclient.TokenSource), as a WebSocket carrying a yamux session; the
// service opens one stream per visitor connection and the client pipes it to
// the local port. Every visitor request still passes the proxy's ForwardAuth.
// The wire protocol is in proto.go.
//
// Unlike iapclient, this package has dependencies outside the standard
// library (github.com/coder/websocket, github.com/hashicorp/yamux).
package expose

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/coder/websocket"
	"github.com/hashicorp/yamux"

	"github.com/R167/iap/iapclient"
)

// Tokens mints access tokens for one exact host; *iapclient.TokenSource is
// one.
type Tokens interface {
	Token(ctx context.Context, host string) (iapclient.Token, error)
}

// Options configures Run.
type Options struct {
	// Name is the host label: the page is https://<Name>.<Domain>.
	Name string
	// Domain is the tunnel service's domain (e.g. iap.example.com); the
	// endpoint is https://tunnel.<Domain> unless Endpoint is set.
	Domain   string
	Endpoint string
	// Backend is the local address requests go to (127.0.0.1:<port>).
	Backend string
	// Reserve keeps the name this long after the last disconnect (0: about a
	// minute). Take moves a name from another of the owner's registrations
	// or processes, on the first connect only.
	Reserve time.Duration
	Take    bool
	// Public claims <Name>.<the service's public domain> instead: served
	// without the IAP, and only where the service's public-page list allows
	// this name for this principal. The connection still goes to the
	// endpoint, through the IAP.
	Public bool
	Tokens Tokens
	// HTTPClient performs the WebSocket handshake. Its Timeout must be 0.
	// Redirects are never followed (a copy is used). Default:
	// http.DefaultClient.
	HTTPClient *http.Client
	// Log receives status lines (the URL once live, reconnects). Default:
	// io.Discard.
	Log io.Writer
	// OnReady is called once, when the page is first live.
	OnReady func(url string)
	// Backoff bounds between failed connects. Defaults 1s and 30s.
	MinBackoff, MaxBackoff time.Duration
	// Now is the clock; default time.Now.
	Now func() time.Time
}

// refreshMargin: a connection is replaced this long before its token (or the
// service's connection age limit) runs out. It is under iapclient's
// minRemaining, so the replacement always gets a freshly minted token.
const refreshMargin = 45 * time.Second

// TakenError: another registration or process of the same owner moved the
// name with --take. Final.
type TakenError struct{ Name, By string }

func (e *TakenError) Error() string {
	return fmt.Sprintf("%s was taken by %s (--take); this process no longer serves it", e.Name, e.By)
}

// SupersededError: another process of the same registration connected for
// the name (the box restarted, or a second `iap expose` of it ran). Final.
type SupersededError struct{ Name string }

func (e *SupersededError) Error() string {
	return fmt.Sprintf("%s was superseded by a new connection from the same registration; this process no longer serves it", e.Name)
}

// RedirectError: the tunnel endpoint answered the handshake with a
// redirect. Behind the IAP that is its sign-in page: the request was not
// authenticated as an agent (the token was not sent or not accepted, or the
// route is not behind the bearer-aware ForwardAuth). Final.
type RedirectError struct {
	Status   int
	Location string
}

func (e *RedirectError) Error() string {
	host := e.Location
	if u, err := url.Parse(e.Location); err == nil && u.Host != "" {
		host = u.Host
	}
	return fmt.Sprintf("the tunnel endpoint redirected the connect (HTTP %d to %s): the IAP did not accept the agent token, most likely sending it to its sign-in page; check the registration (`iap status`) and the endpoint's route", e.Status, host)
}

// ProxyRefusedError: the IAP in front of the tunnel endpoint refused the
// connect (no grant for this agent on the endpoint host). Final.
type ProxyRefusedError struct {
	Status    int
	Code      string
	Principal string
	Host      string
}

func (e *ProxyRefusedError) Error() string {
	if e.Code == "forbidden" {
		return fmt.Sprintf("the IAP refused %s on %s: it needs a grant there (HTTP %d)", e.Principal, e.Host, e.Status)
	}
	return fmt.Sprintf("the IAP refused the connect: HTTP %d %s", e.Status, e.Code)
}

// final reports whether err ends Run rather than being retried.
func final(err error) bool {
	var ref *Refusal
	if errors.As(err, &ref) {
		return ref.Code != CodeUnavailable && ref.Code != CodeRateLimited
	}
	var pr *ProxyRefusedError
	var forbidden *iapclient.ForbiddenError
	var host *iapclient.HostNotAllowedError
	var mismatch *iapclient.IssuerMismatchError
	var taken *TakenError
	var superseded *SupersededError
	var redirect *RedirectError
	return errors.As(err, &pr) || errors.As(err, &forbidden) || errors.As(err, &host) ||
		errors.As(err, &mismatch) || errors.As(err, &taken) || errors.As(err, &superseded) ||
		errors.As(err, &redirect) ||
		errors.Is(err, iapclient.ErrInvalidGrant) || errors.Is(err, iapclient.ErrNotLoggedIn) ||
		errors.Is(err, iapclient.ErrNoCredential)
}

// Run publishes the backend until ctx ends (nil) or the name is lost for
// good (a *Refusal, *TakenError, *ProxyRefusedError or a credential error).
// Network failures and service restarts are retried with backoff.
func Run(ctx context.Context, o Options) error {
	if o.Endpoint == "" {
		o.Endpoint = "https://tunnel." + o.Domain
	}
	ep, err := url.Parse(o.Endpoint)
	if err != nil || ep.Scheme != "https" || ep.Host == "" {
		return fmt.Errorf("tunnel endpoint %q: want https://<host>", o.Endpoint)
	}
	if o.HTTPClient == nil {
		o.HTTPClient = http.DefaultClient
	}
	// A redirect on the handshake is an answer, not a hop to follow: the
	// IAP's sign-in page would otherwise get the upgrade request (and its
	// Proxy-Authorization on a same-host redirect).
	hc := *o.HTTPClient
	hc.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	o.HTTPClient = &hc
	if o.Log == nil {
		o.Log = io.Discard
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.MinBackoff <= 0 {
		o.MinBackoff = time.Second
	}
	if o.MaxBackoff < o.MinBackoff {
		o.MaxBackoff = max(30*time.Second, o.MinBackoff)
	}
	var id [16]byte
	if _, err := rand.Read(id[:]); err != nil {
		return err
	}
	c := &client{o: o, endpoint: ep, instance: hex.EncodeToString(id[:])}
	return c.run(ctx)
}

type client struct {
	o        Options
	endpoint *url.URL
	instance string
}

func (c *client) logf(format string, args ...any) {
	fmt.Fprintf(c.o.Log, "iap expose: "+format+"\n", args...)
}

func (c *client) run(ctx context.Context) error {
	backoff := c.o.MinBackoff
	wait := func() bool {
		t := time.NewTimer(backoff)
		defer t.Stop()
		backoff = min(backoff*2, c.o.MaxBackoff)
		select {
		case <-ctx.Done():
			return false
		case <-t.C:
			return true
		}
	}
	var cur *session
	defer func() {
		if cur != nil {
			cur.close()
		}
	}()
	announced, take := false, c.o.Take
	for {
		if cur == nil {
			s, err := c.dial(ctx, take)
			switch {
			case ctx.Err() != nil:
				return nil
			case err != nil && final(err):
				return err
			case err != nil:
				c.logf("connect failed: %v; retrying in %s", err, backoff)
				if !wait() {
					return nil
				}
				continue
			}
			take = false // only the first connect moves a name
			cur = s
			if !announced {
				announced = true
				c.announce(s.ready)
			} else {
				c.logf("reconnected")
			}
		}
		timer := time.NewTimer(max(cur.refreshAt.Sub(c.o.Now()), 0))
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil
		case <-cur.done:
			timer.Stop()
			reason, by := cur.closing()
			switch reason {
			case ReasonTaken:
				return &TakenError{Name: cur.ready.URL, By: by}
			case ReasonSuperseded:
				return &SupersededError{Name: cur.ready.URL}
			}
			lived := c.o.Now().Sub(cur.connectedAt)
			cur = nil
			if reason == "" {
				reason = "connection lost"
			}
			if lived > 10*time.Second {
				backoff = c.o.MinBackoff
			} else if !wait() {
				return nil
			}
			c.logf("%s; reconnecting", reason)
		case <-timer.C:
			// Make before break: the service moves the name to the new
			// connection and lets the old one finish what it is serving.
			s, err := c.dial(ctx, false)
			switch {
			case ctx.Err() != nil:
				return nil
			case err != nil && final(err):
				return err
			case err != nil:
				c.logf("refreshing the connection failed: %v; retrying in %s", err, backoff)
				cur.refreshAt = c.o.Now().Add(backoff)
				backoff = min(backoff*2, c.o.MaxBackoff)
				continue
			}
			backoff = c.o.MinBackoff
			go cur.drainThenClose()
			cur = s
		}
	}
}

func (c *client) announce(r Control) {
	msg := fmt.Sprintf("%s -> %s", r.URL, c.o.Backend)
	if r.ReserveSeconds > 0 {
		msg += fmt.Sprintf(" (reserved for %s after the last disconnect)", time.Duration(r.ReserveSeconds)*time.Second)
	}
	if r.TookFrom != "" {
		msg += " (taken from " + r.TookFrom + ")"
	}
	c.logf("%s", msg)
	if c.o.OnReady != nil {
		c.o.OnReady(r.URL)
	}
}

// session is one tunnel connection.
type session struct {
	ys          *yamux.Session
	ready       Control
	connectedAt time.Time
	refreshAt   time.Time
	done        <-chan struct{}

	mu     sync.Mutex
	reason string
	by     string
}

func (s *session) closing() (string, string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.reason, s.by
}

func (s *session) close() { _ = s.ys.Close() }

// drainThenClose waits for the service to close a replaced connection once
// its requests finish, and closes it anyway at its deadline.
func (s *session) drainThenClose() {
	t := time.NewTimer(time.Duration(s.ready.MaxAgeSeconds)*time.Second + refreshMargin)
	defer t.Stop()
	select {
	case <-s.done:
	case <-t.C:
		s.close()
	}
}

// dial opens one connection and waits for the service's ready (or refusal).
func (c *client) dial(ctx context.Context, take bool) (*session, error) {
	host := strings.ToLower(c.endpoint.Hostname())
	tok, err := c.o.Tokens.Token(ctx, host)
	if err != nil {
		return nil, err
	}
	q := url.Values{QueryName: {c.o.Name}}
	if c.o.Reserve > 0 {
		q.Set(QueryReserve, strconv.Itoa(int(c.o.Reserve/time.Second)))
	}
	if take {
		q.Set(QueryTake, "1")
	}
	if c.o.Public {
		q.Set(QueryPublic, "1")
	}
	u := *c.endpoint
	u.Path, u.RawQuery = ConnectPath, q.Encode()
	hdr := http.Header{}
	hdr.Set("Proxy-Authorization", "Bearer "+tok.Value.Reveal())
	hdr.Set(InstanceHeader, c.instance)

	dialCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	connectedAt := c.o.Now()
	ws, resp, err := websocket.Dial(dialCtx, u.String(), &websocket.DialOptions{
		HTTPClient:      c.o.HTTPClient,
		HTTPHeader:      hdr,
		CompressionMode: websocket.CompressionDisabled,
	})
	if err != nil {
		if resp != nil {
			return nil, refusalFrom(resp, host)
		}
		return nil, err
	}
	// The NetConn lives until the session closes, not until dial returns.
	nc := websocket.NetConn(context.WithoutCancel(ctx), ws, websocket.MessageBinary)
	ys, err := yamux.Server(nc, clientYamuxConfig())
	if err != nil {
		_ = nc.Close()
		return nil, err
	}
	ctrl, err := acceptTimeout(ys, 30*time.Second)
	if err != nil {
		_ = ys.Close()
		return nil, fmt.Errorf("no control stream: %w", err)
	}
	br := bufio.NewReader(ctrl)
	var first Control
	if err := readControl(br, &first); err != nil {
		_ = ys.Close()
		return nil, fmt.Errorf("control stream: %w", err)
	}
	switch first.Type {
	case TypeReady:
	case TypeRefused:
		_ = ys.Close()
		return nil, &Refusal{Code: first.Error, Message: first.Message, Holder: first.Holder}
	default:
		_ = ys.Close()
		return nil, fmt.Errorf("control stream: unexpected %q", first.Type)
	}

	done := make(chan struct{})
	s := &session{ys: ys, ready: first, connectedAt: connectedAt, done: done}
	limit := connectedAt.Add(time.Duration(first.MaxAgeSeconds) * time.Second)
	if first.MaxAgeSeconds <= 0 || (!tok.Expiry.IsZero() && tok.Expiry.Before(limit)) {
		limit = tok.Expiry
	}
	if limit.IsZero() {
		limit = connectedAt.Add(15 * time.Minute)
	}
	s.refreshAt = limit.Add(-refreshMargin)
	if floor := connectedAt.Add(2 * time.Second); s.refreshAt.Before(floor) {
		s.refreshAt = floor
	}

	// done closes once the session has ended AND the control stream has been
	// read to its end: the closing reason is written just before the session
	// closes, and must be seen before the run loop decides what the end means
	// (a superseded or taken name must not reconnect).
	var ended sync.WaitGroup
	ended.Add(2)
	go func() {
		ended.Wait()
		close(done)
	}()
	go func() {
		defer ended.Done()
		for {
			var m Control
			if err := readControl(br, &m); err != nil {
				return
			}
			if m.Type == TypeClosing {
				s.mu.Lock()
				s.reason, s.by = m.Reason, m.By
				s.mu.Unlock()
			}
		}
	}()
	go func() {
		defer ended.Done()
		for {
			st, err := ys.Accept()
			if err != nil {
				return
			}
			go pipe(st, c.o.Backend)
		}
	}()
	return s, nil
}

// refusalFrom turns a non-101 handshake response into an error: the
// service's own Refusal, the IAP's refusal, or a transient HTTP error.
func refusalFrom(resp *http.Response, host string) error {
	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		return &RedirectError{Status: resp.StatusCode, Location: resp.Header.Get("Location")}
	}
	var body struct {
		Error     string `json:"error"`
		Message   string `json:"message"`
		Holder    string `json:"holder"`
		Principal string `json:"principal"`
	}
	if resp.Body != nil {
		// The first value only: trailing bytes are not an error.
		_ = json.UnmarshalDecode(jsontext.NewDecoder(io.LimitReader(resp.Body, 4096)), &body)
	}
	switch body.Error {
	case CodeInvalidName, CodeReservedName, CodeNameTaken, CodeQuota, CodeBadRequest, CodeNotAgent, CodeUnauthenticated,
		CodeUnavailable, CodeRateLimited, CodePublicDenied:
		return &Refusal{Code: body.Error, Message: body.Message, Holder: body.Holder}
	}
	if resp.StatusCode == http.StatusForbidden {
		return &ProxyRefusedError{Status: resp.StatusCode, Code: body.Error, Principal: body.Principal, Host: host}
	}
	return fmt.Errorf("tunnel endpoint: HTTP %d %s", resp.StatusCode, body.Error)
}

func readControl(br *bufio.Reader, m *Control) error {
	line, err := br.ReadBytes('\n')
	if err != nil {
		return err
	}
	return json.Unmarshal(line, m)
}

func acceptTimeout(ys *yamux.Session, d time.Duration) (net.Conn, error) {
	type res struct {
		c   net.Conn
		err error
	}
	ch := make(chan res, 1)
	go func() {
		c, err := ys.Accept()
		ch <- res{c, err}
	}()
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case r := <-ch:
		return r.c, r.err
	case <-t.C:
		return nil, errors.New("timed out")
	}
}

func clientYamuxConfig() *yamux.Config {
	cfg := yamux.DefaultConfig()
	cfg.KeepAliveInterval = 20 * time.Second
	cfg.ConnectionWriteTimeout = 15 * time.Second
	cfg.LogOutput = io.Discard
	return cfg
}

// badGateway is written on a stream when the local port refuses: the
// service reads it as the response.
const badGateway = "HTTP/1.1 502 Bad Gateway\r\nContent-Type: text/plain; charset=utf-8\r\nConnection: close\r\nContent-Length: %d\r\n\r\n%s"

// pipe copies one stream to a fresh connection to backend and back. Each
// direction half-closes when it ends, so request bodies and upgraded
// connections (WebSockets) work.
func pipe(st net.Conn, backend string) {
	defer st.Close()
	bc, err := net.DialTimeout("tcp", backend, 5*time.Second)
	if err != nil {
		msg := "nothing is listening on " + backend + " on the publishing machine\n"
		_ = st.SetWriteDeadline(time.Now().Add(5 * time.Second))
		_, _ = fmt.Fprintf(st, badGateway, len(msg), msg)
		return
	}
	defer bc.Close()
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		_, _ = io.Copy(bc, st)
		if tc, ok := bc.(*net.TCPConn); ok {
			_ = tc.CloseWrite()
		}
	}()
	go func() {
		defer wg.Done()
		_, _ = io.Copy(st, bc)
		_ = st.Close() // yamux Close is a half-close (FIN); reads continue
	}()
	wg.Wait()
}
