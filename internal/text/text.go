// Package text makes strings from packages, indexes and bundles safe to print on a
// terminal: they are written by whoever holds a repository's key.
package text

import (
	"strconv"
	"strings"
	"unicode"
)

// Safe escapes control characters, including newlines and the Unicode controls that
// reorder text, so a value cannot move the cursor, start an escape sequence or pass
// itself off as a line of apt-attest's own output.
func Safe(s string) string {
	if !needsEscape(s) {
		return s
	}
	var b strings.Builder
	for _, r := range s {
		if unsafeRune(r) {
			q := strconv.QuoteRuneToASCII(r)
			b.WriteString(q[1 : len(q)-1])
		} else {
			b.WriteRune(r)
		}
	}
	return b.String()
}

func needsEscape(s string) bool {
	for _, r := range s {
		if unsafeRune(r) {
			return true
		}
	}
	return false
}

func unsafeRune(r rune) bool {
	return r == unicode.ReplacementChar || unicode.IsControl(r) || unicode.Is(unicode.Bidi_Control, r) ||
		unicode.In(r, unicode.Zl, unicode.Zp)
}
