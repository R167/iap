package cli

import (
	"fmt"
	"strings"
)

// curlOption is one curl option `iap curl` passes through.
type curlOption struct {
	long  string
	short byte // 0 when it has no short form
	value bool // takes an argument
}

// allowedCurlOptions is the whole list: anything else is refused, including
// every option that prints request headers (-v, --trace*, --libcurl), reads
// options from elsewhere (-K), sends the header to another host or through
// something that can read it (a second URL, --next, -L, --resolve,
// --connect-to, -x and the proxy options, --unix-socket, --interface,
// --dns-servers) or turns off certificate checks (-k, --cacert, --capath).
// Abbreviated long options are refused too: only exact names match.
var allowedCurlOptions = []curlOption{
	{"silent", 's', false},
	{"show-error", 'S', false},
	{"fail", 'f', false},
	{"fail-with-body", 0, false},
	{"include", 'i', false},
	{"head", 'I', false},
	{"request", 'X', true},
	{"header", 'H', true},
	{"data", 'd', true},
	{"data-raw", 0, true},
	{"data-binary", 0, true},
	{"data-urlencode", 0, true},
	{"json", 0, true},
	{"form", 'F', true},
	{"output", 'o', true},
	{"remote-name", 'O', false},
	{"write-out", 'w', true},
	{"compressed", 0, false},
	{"max-time", 0, true},
	{"connect-timeout", 0, true},
	{"get", 'G', false},
	{"user-agent", 'A', true},
	{"referer", 'e', true},
	{"retry", 0, true},
	{"cookie", 'b', true},
	{"range", 'r', true},
}

// refusedHeaders may not be set with -H: the credential, a competing one,
// and Host (which would bind the request to another virtual host).
var refusedHeaders = map[string]bool{"proxy-authorization": true, "authorization": true, "host": true}

// curlOptionsHelp lists the allowlist for --help.
func curlOptionsHelp() string {
	var b strings.Builder
	b.WriteString("curl options allowed after the URL:")
	for _, o := range allowedCurlOptions {
		b.WriteString("\n  ")
		if o.short != 0 {
			fmt.Fprintf(&b, "-%c, ", o.short)
		}
		b.WriteString("--" + o.long)
		if o.value {
			b.WriteString(" <v>")
		}
	}
	b.WriteString("\n-H may not set Proxy-Authorization, Authorization or Host, or read a file (@).")
	return b.String()
}

func lookupLong(name string) (curlOption, bool) {
	for _, o := range allowedCurlOptions {
		if o.long == name {
			return o, true
		}
	}
	return curlOption{}, false
}

func lookupShort(c byte) (curlOption, bool) {
	for _, o := range allowedCurlOptions {
		if o.short != 0 && o.short == c {
			return o, true
		}
	}
	return curlOption{}, false
}

// checkCurlArgs accepts only allowedCurlOptions, in --opt, --opt=value,
// --opt value, -x value, -xvalue and clustered (-sSf) forms, and returns the
// arguments to hand curl: identical, except that --opt=value (which curl
// itself rejects) becomes --opt value. A positional argument is refused: curl
// would take it as a second URL and send the header there too.
func checkCurlArgs(args []string) ([]string, error) {
	out := make([]string, 0, len(args))
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case strings.HasPrefix(a, "--") && len(a) > 2:
			name, val, hasVal := strings.Cut(a[2:], "=")
			o, ok := lookupLong(name)
			if !ok {
				return nil, fmt.Errorf("refusing curl option --%s: not on the allowlist (%s curl --help)", name, cmdName())
			}
			switch {
			case !o.value && hasVal:
				return nil, fmt.Errorf("curl option --%s takes no value", name)
			case o.value && !hasVal:
				if i+1 >= len(args) {
					return nil, fmt.Errorf("curl option --%s needs a value", name)
				}
				i++
				val = args[i]
			}
			if err := checkOptionValue(o, val); err != nil {
				return nil, err
			}
			out = append(out, "--"+name)
			if o.value {
				out = append(out, val)
			}
		case strings.HasPrefix(a, "-") && len(a) > 1 && a != "--":
			out = append(out, a)
			cluster := a[1:]
			for j := 0; j < len(cluster); j++ {
				o, ok := lookupShort(cluster[j])
				if !ok {
					return nil, fmt.Errorf("refusing curl option -%c (in %q): not on the allowlist (%s curl --help)", cluster[j], a, cmdName())
				}
				if !o.value {
					continue
				}
				val := cluster[j+1:]
				if val == "" {
					if i+1 >= len(args) {
						return nil, fmt.Errorf("curl option -%c needs a value", cluster[j])
					}
					i++
					val = args[i]
					out = append(out, val)
				}
				if err := checkOptionValue(o, val); err != nil {
					return nil, err
				}
				break
			}
		default:
			return nil, fmt.Errorf("refusing %q: curl would take it as another URL and send the token there too; pass one URL, first", a)
		}
	}
	return out, nil
}

// checkOptionValue vets a -H value: no @file form (the file could carry any
// header), no line breaks, and none of refusedHeaders.
func checkOptionValue(o curlOption, val string) error {
	if o.long != "header" {
		return nil
	}
	if strings.HasPrefix(val, "@") {
		return fmt.Errorf("refusing -H %q: header files are not allowed", val)
	}
	if strings.ContainsAny(val, "\r\n") {
		return fmt.Errorf("refusing -H with a line break")
	}
	name := val
	if i := strings.IndexAny(val, ":;"); i >= 0 {
		name = val[:i]
	}
	if refusedHeaders[strings.ToLower(strings.TrimSpace(name))] {
		return fmt.Errorf("refusing -H %s: iap curl sets the credential itself", strings.TrimSpace(name))
	}
	return nil
}
