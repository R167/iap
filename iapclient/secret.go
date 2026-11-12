package iapclient

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"time"
)

const redacted = "<redacted>"

// Secret holds a credential (an access token or the refresh credential). It
// never prints: String, GoString, every fmt verb and slog give "<redacted>",
// and JSON or text marshalling fails. Reveal is the only way to the value.
type Secret struct{ v string }

// NewSecret wraps a credential.
func NewSecret(v string) Secret { return Secret{v: v} }

// Reveal returns the credential. Call it only to put the value on the wire
// or into a store; never log or print the result.
func (s Secret) Reveal() string { return s.v }

// IsZero reports whether s holds nothing.
func (s Secret) IsZero() bool { return s.v == "" }

func (Secret) String() string                 { return redacted }
func (Secret) GoString() string               { return redacted }
func (Secret) Format(f fmt.State, _ rune)     { _, _ = io.WriteString(f, redacted) }
func (Secret) LogValue() slog.Value           { return slog.StringValue(redacted) }
func (Secret) MarshalJSON() ([]byte, error)   { return nil, errMarshal }
func (Secret) MarshalText() ([]byte, error)   { return nil, errMarshal }
func (Secret) MarshalBinary() ([]byte, error) { return nil, errMarshal }

var errMarshal = errors.New("iapclient: refusing to marshal a credential")

// Token is an access token minted for one host. Printing a Token shows
// everything but the credential.
type Token struct {
	Value     Secret
	Host      string    // the exact host it was minted for
	Principal string    // agent:user:<email>:<machine>:<program>:<session>
	Expiry    time.Time // zero when the issuer gave no lifetime
}
