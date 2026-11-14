package identity

import (
	"fmt"
	"regexp"
	"strings"
)

// Principal kinds and agent types a verified identity can have.
const (
	KindUser  = "user"
	KindSA    = "sa"
	KindAgent = "agent"

	AgentUser = "user" // agent:user:<email>:<machine>:<program>:<session>, owned by user:<email>
	AgentK8s  = "k8s"  // agent:k8s:<cluster>:<workload>, no owner
)

// Identity is a verified caller.
type Identity struct {
	Principal string // canonical, e.g. user:alice@example.com
	Kind      string // KindUser, KindSA or KindAgent
	AgentType string // KindAgent only: AgentUser or AgentK8s
	Email     string // KindUser only
	Owner     string // agent:user only: user:<email>
}

// The same rules the issuer applies when it parses a principal.
var (
	agentSegmentRE = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,62}$`)
	dnsLabelRE     = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`)
)

func validEmail(e string) bool {
	local, domain, ok := strings.Cut(e, "@")
	if !ok || local == "" || domain == "" || strings.Contains(domain, "@") {
		return false
	}
	return !strings.ContainsAny(e, " \t\r\n,;:<>\"*")
}

func validDNSLabel(s string) bool { return len(s) <= 63 && dnsLabelRE.MatchString(s) }

func validDNSSubdomain(s string) bool {
	if s == "" || len(s) > 253 {
		return false
	}
	for _, label := range strings.Split(s, ".") {
		if !validDNSLabel(label) {
			return false
		}
	}
	return true
}

// ParsePrincipal parses a canonical (lowercase) concrete principal of a
// known type. Patterns, group: and gh: (grant-side names, never a caller),
// agent:test (which nothing can present to the proxy) and unknown types are
// errors.
func ParsePrincipal(s string) (Identity, error) {
	if s != strings.ToLower(s) {
		return Identity{}, fmt.Errorf("principal %q is not canonical (lowercase)", s)
	}
	kind, value, ok := strings.Cut(s, ":")
	if !ok || value == "" {
		return Identity{}, fmt.Errorf("principal %q: want <kind>:<value>", s)
	}
	id := Identity{Principal: s, Kind: kind}
	switch kind {
	case KindUser:
		if !validEmail(value) {
			return Identity{}, fmt.Errorf("principal %q: invalid email", s)
		}
		id.Email = value
	case KindSA:
		ns, name, ok := strings.Cut(value, "/")
		if !ok || !validDNSLabel(ns) || !validDNSSubdomain(name) {
			return Identity{}, fmt.Errorf("principal %q: want sa:<namespace>/<name>", s)
		}
	case KindAgent:
		segs := strings.Split(value, ":")
		id.AgentType = segs[0]
		switch id.AgentType {
		case AgentUser:
			if len(segs) != 5 || !validEmail(segs[1]) {
				return Identity{}, fmt.Errorf("principal %q: want agent:user:<email>:<machine>:<program>:<session>", s)
			}
			for _, seg := range segs[2:] {
				if !agentSegmentRE.MatchString(seg) {
					return Identity{}, fmt.Errorf("principal %q: invalid segment %q", s, seg)
				}
			}
			id.Owner = KindUser + ":" + segs[1]
		case AgentK8s:
			if len(segs) != 3 || !validDNSLabel(segs[1]) || !validDNSLabel(segs[2]) {
				return Identity{}, fmt.Errorf("principal %q: want agent:k8s:<cluster>:<workload>", s)
			}
		default:
			return Identity{}, fmt.Errorf("principal %q: agent type %q is not a caller", s, id.AgentType)
		}
	default:
		return Identity{}, fmt.Errorf("principal %q: kind %q is not a caller", s, kind)
	}
	return id, nil
}
