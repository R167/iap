package iapclient

import (
	"fmt"
	"net/url"
	"regexp"
	"strings"
)

// segmentRE is the issuer's rule for machine, program and session segments.
var segmentRE = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,62}$`)

// hostnameRE is a lowercase DNS name of at least two labels.
var hostnameRE = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$`)

// dnsName reports whether s is a lowercase DNS name of at least two labels
// whose last label is not all digits (so no IPv4 literal).
func dnsName(s string) bool {
	if !hostnameRE.MatchString(s) {
		return false
	}
	tld := s[strings.LastIndex(s, ".")+1:]
	return strings.Trim(tld, "0123456789") != ""
}

// SegmentPattern is the pattern machine, program and session must match.
const SegmentPattern = `^[a-z0-9][a-z0-9._-]{0,62}$`

// ValidSegment reports whether s is a valid machine, program or session.
func ValidSegment(s string) bool { return segmentRE.MatchString(s) }

// SanitizeSegment lowercases s and maps it onto the segment rule, or "".
func SanitizeSegment(s string) string {
	s = strings.ToLower(s)
	var b strings.Builder
	for _, c := range s {
		if c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '.' || c == '_' || c == '-' {
			b.WriteRune(c)
		} else {
			b.WriteByte('-')
		}
	}
	out := strings.TrimLeft(b.String(), "._-")
	if len(out) > 63 {
		out = out[:63]
	}
	if !segmentRE.MatchString(out) {
		return ""
	}
	return out
}

// ParseIssuer checks that raw is https://<host> with at least three labels
// (the issuer's own domain is the host minus its first label) and nothing
// else: no port, path, query, fragment or userinfo. It returns the issuer
// normalised (lowercase host, no trailing slash). The refresh credential is
// posted there, so nothing looser is accepted.
func ParseIssuer(raw string) (string, error) {
	s := strings.TrimRight(raw, "/")
	u, err := url.Parse(s)
	bad := fmt.Errorf("issuer %q: want https://<host> with no port or path", raw)
	if err != nil || u.Scheme != "https" || u.User != nil || u.Port() != "" || u.Path != "" || u.RawQuery != "" || u.Fragment != "" || u.Opaque != "" {
		return "", bad
	}
	host := strings.ToLower(u.Hostname())
	if !dnsName(host) || strings.Count(host, ".") < 2 {
		return "", bad
	}
	return "https://" + host, nil
}

// issuerDomain is the suffix the issuer mints for without being told:
// ".<issuer host minus its first label>" (https://access.example.com →
// ".example.com"). issuer must have passed ParseIssuer.
func issuerDomain(issuer string) string {
	host := strings.TrimPrefix(issuer, "https://")
	_, rest, _ := strings.Cut(host, ".")
	return "." + rest
}

// normalizeSuffix maps an advertised suffix ("example.org" or
// ".example.org") to ".example.org", or "" when it is not a DNS name of
// at least two labels.
func normalizeSuffix(s string) string {
	s = strings.TrimPrefix(strings.ToLower(strings.TrimSpace(s)), ".")
	if !dnsName(s) {
		return ""
	}
	return "." + s
}

// hostAllowed reports whether host (lowercase, no port) is a plain DNS name
// strictly under one of suffixes.
func hostAllowed(host string, suffixes []string) bool {
	if !dnsName(host) {
		return false
	}
	for _, sfx := range suffixes {
		if len(host) > len(sfx) && strings.HasSuffix(host, sfx) {
			return true
		}
	}
	return false
}

// requestHost returns u's lowercase host when u is https with no userinfo,
// and whether that host is under suffixes.
func requestHost(u *url.URL, suffixes []string) (string, bool) {
	if u == nil || u.Scheme != "https" || u.User != nil {
		return "", false
	}
	host := strings.ToLower(u.Hostname())
	return host, hostAllowed(host, suffixes)
}

func displaySuffixes(suffixes []string) string {
	out := make([]string, len(suffixes))
	for i, s := range suffixes {
		out[i] = strings.TrimPrefix(s, ".")
	}
	return strings.Join(out, ", ")
}
