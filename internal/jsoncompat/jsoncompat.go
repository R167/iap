// Package jsoncompat holds the encoding/json/v2 options that keep this
// module's JSON readable and writable by encoding/json (v1) peers: the
// iap-authz issuer, the iap-tunnel server, and config and credential files
// written by releases built on v1. See CLAUDE.md, "JSON".
package jsoncompat

import (
	"encoding/json/jsontext"
	"encoding/json/v2"
)

// Read is for decoding anything a v1 encoder may have written or a v1
// decoder would have accepted. v2's stricter defaults would otherwise
// reject or misread legitimate input:
//
//   - MatchCaseInsensitiveNames: v1 matched object names to struct fields
//     case-insensitively ("Account" filled `json:"account"`); v2 by default
//     ignores such a member silently.
//   - AllowDuplicateNames: v1 accepted a repeated name (the last one wins);
//     v2 by default fails the whole decode.
//   - AllowInvalidUTF8: v1 replaced invalid UTF-8 in strings with U+FFFD; v2
//     by default fails the whole decode.
//
// Unknown members are ignored by both versions; nothing is needed for them.
var Read = json.JoinOptions(
	json.MatchCaseInsensitiveNames(true),
	jsontext.AllowDuplicateNames(true),
	jsontext.AllowInvalidUTF8(true),
)

// Write is for encoding anything a v1 decoder may read (the wire protocol)
// or that should stay byte-identical to what a v1 build wrote (config.json,
// credentials.json):
//
//   - FormatNilSliceAsNull, FormatNilMapAsNull: v1 wrote a nil slice or map
//     as null; v2 by default writes [] or {}.
//   - Deterministic: v1 sorted map keys; v2 by default does not.
//   - EscapeForHTML, EscapeForJS: v1 escaped <, >, & and U+2028/U+2029;
//     both versions read either form, this only keeps the bytes the same.
//
// omitempty differs too, but per field, not per call: v2 omits a field only
// when it would encode as null, "", {} or [], so a zero number or false is
// still written. Fields where v1's omitempty dropped 0 or false are tagged
// omitzero instead (v1 honours omitzero since Go 1.24).
var Write = json.JoinOptions(
	json.FormatNilSliceAsNull(true),
	json.FormatNilMapAsNull(true),
	json.Deterministic(true),
	jsontext.EscapeForHTML(true),
	jsontext.EscapeForJS(true),
)

// File is Write with the two-space indent of v1's MarshalIndent(v, "", "  ").
var File = json.JoinOptions(Write, jsontext.WithIndent("  "))
