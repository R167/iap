package expose

import (
	"encoding/json/v2"
	"fmt"
	"regexp"
)

// The wire protocol between `iap expose` and the tunnel service
// (the iap-tunnel server), which imports these definitions so the two never
// drift. Changing anything here is a protocol change: see CLAUDE.md.
//
//  1. The client sends GET https://tunnel.<domain>/v1/connect as a WebSocket
//     upgrade, with Proxy-Authorization: Bearer <agent token for
//     tunnel.<domain>> (the IAP's ForwardAuth checks it and hands the
//     service X-IAP-Identity) and InstanceHeader. Query: QueryName,
//     optional QueryReserve (whole seconds), QueryTake=1 and QueryPublic=1
//     (claim <name>.<public domain>, served without the IAP, instead of
//     <name>.<domain>).
//  2. A refusal is a plain HTTP response with a JSON Refusal body. Anything
//     else non-101 (the IAP's 401/403, a 5xx) is not the service speaking.
//  3. After the upgrade, binary WebSocket messages carry a yamux session:
//     the service is the yamux client and opens streams, the CLI the yamux
//     server. The first stream is the control stream: the service writes
//     one JSON Control message per line (Ready, then possibly Closing).
//  4. Every later stream is one connection to the CLI's local port: the
//     service writes an HTTP/1.1 request on it (keep-alive and Upgrade
//     included) and the CLI pipes the bytes both ways to 127.0.0.1:<port>.
const (
	ConnectPath    = "/v1/connect"
	QueryName      = "name"
	QueryReserve   = "reserve"
	QueryTake      = "take"
	QueryPublic    = "public"
	InstanceHeader = "X-IAP-Tunnel-Instance"

	// MaxReserve is the longest reservation: 30 days after the last
	// disconnect, renewed by every connect. Independent of the
	// registration's own expiry.
	MaxReserve = 30 * 24 * 60 * 60 // seconds
)

// InstanceRE is an instance id: random hex the CLI picks once per process,
// so the service tells a reconnect of the same process from another one.
var InstanceRE = regexp.MustCompile(`^[0-9a-f]{16,64}$`)

// Refusal codes. All are final for the CLI except CodeUnavailable and
// CodeRateLimited.
const (
	CodeInvalidName     = "invalid_name"          // syntax or IDN
	CodeReservedName    = "reserved_name"         // a name the service keeps for itself
	CodeNameTaken       = "name_taken"            // another owner holds it, or it is live/reserved without --take
	CodeQuota           = "quota_exceeded"        // the owner holds the maximum number of names
	CodeBadRequest      = "bad_request"           // a malformed parameter
	CodeNotAgent        = "principal_not_allowed" // a principal kind that may not open tunnels
	CodeUnauthenticated = "unauthenticated"       // no or invalid X-IAP-Identity
	CodeUnavailable     = "unavailable"           // the service could not persist the reservation; retry
	CodeRateLimited     = "rate_limited"          // too many connects or open connections for this owner, or the service is full; retry
	CodePublicDenied    = "public_not_allowed"    // --public: no public-page entry allows this name for this principal, or public pages are off
)

// Refusal is the JSON body of a refused connect.
type Refusal struct {
	Code    string `json:"error"`
	Message string `json:"message"`
	// Holder is the registration holding a taken name, when it has the
	// caller's owner (so the caller can decide on --take). Never set for
	// another owner's name.
	Holder string `json:"holder,omitempty"`
}

func (r *Refusal) Error() string { return fmt.Sprintf("%s: %s", r.Code, r.Message) }

// Control message types.
const (
	TypeReady   = "ready"
	TypeClosing = "closing"
	// TypeRefused: the claim was refused after the upgrade (another
	// connect won the name in between); Error/Message/Holder as in Refusal.
	TypeRefused = "refused"
)

// Closing reasons.
const (
	ReasonTaken    = "taken"    // another registration of the same owner used --take; final
	ReasonReplaced = "replaced" // this process connected again; the old connection drains
	// ReasonSuperseded: another process of the same registration connected
	// (the box restarted before the service noticed); final for this one.
	ReasonSuperseded = "superseded"
	ReasonMaxAge     = "max_age"  // the connection outlived its token's longest lifetime; reconnect
	ReasonShutdown   = "shutdown" // the service is stopping; reconnect
	ReasonInternal   = "internal" // the service failed to record the claim; reconnect
)

// Control is one line on the control stream.
type Control struct {
	Type string `json:"type"`
	// Ready.
	URL            string `json:"url,omitempty"`
	MaxAgeSeconds  int    `json:"max_age_seconds,omitzero"`
	ReserveSeconds int    `json:"reserve_seconds,omitzero"`
	TookFrom       string `json:"took_from,omitempty"` // the registration --take moved the name from
	// Closing.
	Reason string `json:"reason,omitempty"`
	By     string `json:"by,omitempty"` // ReasonTaken: the registration that took it
	// Refused.
	Error   string `json:"error,omitempty"`
	Message string `json:"message,omitempty"`
	Holder  string `json:"holder,omitempty"`
}

// MarshalLine renders c as one JSON line.
func (c Control) MarshalLine() []byte {
	b, _ := json.Marshal(c)
	return append(b, '\n')
}
