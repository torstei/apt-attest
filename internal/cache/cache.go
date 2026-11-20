// Package cache keeps the claims of attestations that have verified, keyed by the
// package's SHA256, so a reinstall needs neither the bundle nor the network. The claims
// are checked against the current policy on every use, so a policy change still applies.
package cache

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"

	"github.com/torstei/apt-attest/internal/policy"
)

var hexSHA256 = regexp.MustCompile(`^[0-9a-f]{64}$`)

type Cache struct{ Dir string }

func (c Cache) path(sha string) (string, bool) {
	if c.Dir == "" || !hexSHA256.MatchString(sha) {
		return "", false
	}
	return filepath.Join(c.Dir, sha+".json"), true
}

func (c Cache) Get(sha string) (policy.Claims, bool) {
	var claims policy.Claims
	p, ok := c.path(sha)
	if !ok {
		return claims, false
	}
	data, err := os.ReadFile(p)
	if err != nil || json.Unmarshal(data, &claims) != nil {
		return claims, false
	}
	return claims, true
}

// Put is best effort: a failure to cache only costs a later re-verification.
func (c Cache) Put(sha string, claims policy.Claims) {
	p, ok := c.path(sha)
	if !ok {
		return
	}
	data, err := json.Marshal(claims)
	if err != nil {
		return
	}
	if os.MkdirAll(c.Dir, 0o755) != nil {
		return
	}
	tmp := p + ".tmp"
	if os.WriteFile(tmp, data, 0o644) == nil {
		_ = os.Rename(tmp, p)
	}
}
