// Package app decides, for each package about to be installed, which policies cover it
// and whether its attestation satisfies them.
package app

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/torstei/apt-attest/internal/aptsource"
	"github.com/torstei/apt-attest/internal/attest"
	"github.com/torstei/apt-attest/internal/cache"
	"github.com/torstei/apt-attest/internal/fetch"
	"github.com/torstei/apt-attest/internal/policy"
	"github.com/torstei/apt-attest/internal/text"
	"github.com/torstei/apt-attest/internal/trustroot"
)

const BundleSuffix = ".sigstore.json"

type Package struct {
	Name    string
	Version string
	File    string
	SHA256  string
	Sources []aptsource.Source
}

type Engine struct {
	Policies []*policy.Policy
	StateDir string
	Fetcher  *fetch.Fetcher
	Out      io.Writer
	// IndexTargets lists apt's Packages indexes; replaceable in tests.
	IndexTargets func() ([]aptsource.IndexTarget, error)
	// BundlePath, if set, is used instead of looking for the bundle.
	BundlePath string
	// NoCache makes every check verify the bundle again.
	NoCache bool
	// ArchivesDir is where apt keeps the packages it downloads. When set, and a policy
	// matches by origin, a package there that no index accounts for is refused.
	ArchivesDir string

	verifier *attest.Verifier
	rootName string
}

func (e *Engine) cache() cache.Cache {
	if e.NoCache || e.StateDir == "" {
		return cache.Cache{}
	}
	return cache.Cache{Dir: filepath.Join(e.StateDir, "verified")}
}

func (e *Engine) anyOrigins() bool {
	for _, p := range e.Policies {
		if p.HasOrigins() {
			return true
		}
	}
	return false
}

func (e *Engine) matchesName(name string) bool {
	for _, p := range e.Policies {
		if p.Matches(name, nil) {
			return true
		}
	}
	return false
}

// Candidates returns the packages any policy might cover: all of them when a policy
// matches by origin, since an unattested package can arrive under any name.
func (e *Engine) Candidates(pkgs []Package) []Package {
	if e.anyOrigins() {
		return pkgs
	}
	var out []Package
	for _, p := range pkgs {
		if e.matchesName(p.Name) {
			out = append(out, p)
		}
	}
	return out
}

// Locate fills in each package's SHA256 and the apt sources that carry that exact file.
func (e *Engine) Locate(pkgs []Package) error {
	var wants []string
	for i := range pkgs {
		if pkgs[i].SHA256 == "" {
			sum, err := FileSHA256(pkgs[i].File)
			if err != nil {
				return err
			}
			pkgs[i].SHA256 = sum
		}
		wants = append(wants, pkgs[i].SHA256)
	}
	if len(wants) == 0 {
		return nil
	}
	list := e.IndexTargets
	if list == nil {
		list = aptsource.IndexTargets
	}
	targets, err := list()
	if err != nil {
		return err
	}
	found, err := aptsource.Lookup(targets, wants)
	if err != nil {
		return err
	}
	for i := range pkgs {
		pkgs[i].Sources = found[strings.ToLower(pkgs[i].SHA256)]
	}
	return nil
}

// Covering returns the policies that apply to a located package.
func (e *Engine) Covering(p Package) []*policy.Policy {
	var origins []string
	for _, s := range p.Sources {
		if o, err := policy.NormalizeOrigin(s.RepoURI); err == nil {
			origins = append(origins, o)
		}
	}
	var out []*policy.Policy
	for _, pol := range e.Policies {
		if pol.Matches(p.Name, origins) {
			out = append(out, pol)
		}
	}
	return out
}

func (e *Engine) Verifier() (*attest.Verifier, error) {
	if e.verifier != nil {
		return e.verifier, nil
	}
	tr, name, err := trustroot.Load(e.StateDir)
	if err != nil {
		return nil, err
	}
	v, err := attest.NewVerifier(tr)
	if err != nil {
		return nil, err
	}
	e.verifier, e.rootName = v, name
	return v, nil
}

// bundleLocations lists where a package's bundle may be, nearest first: beside the
// local file (an `apt install ./x.deb`), then beside the package on each source.
func (e *Engine) bundleLocations(p Package) []string {
	if e.BundlePath != "" {
		return []string{e.BundlePath}
	}
	locs := []string{p.File + BundleSuffix}
	for _, s := range p.Sources {
		if u, err := s.URL(); err == nil {
			locs = append(locs, u+BundleSuffix)
		}
	}
	return locs
}

func (e *Engine) untraceable(p Package) bool {
	if e.ArchivesDir == "" || len(p.Sources) > 0 || !e.anyOrigins() {
		return false
	}
	return filepath.Dir(filepath.Clean(p.File)) == filepath.Clean(e.ArchivesDir)
}

// Claims returns the verified claims for a package, from the cache or by fetching and
// verifying its bundle.
func (e *Engine) Claims(p Package, useCache bool) (policy.Claims, string, error) {
	c := e.cache()
	if useCache {
		if claims, ok := c.Get(p.SHA256); ok {
			return claims, "cache", nil
		}
	}
	v, err := e.Verifier()
	if err != nil {
		return policy.Claims{}, "", err
	}
	var tried []string
	for _, s := range p.Sources {
		if _, err := s.URL(); err != nil {
			tried = append(tried, text.Safe(err.Error()))
		}
	}
	verifyFailed := false
	for _, loc := range e.bundleLocations(p) {
		var data []byte
		if !strings.Contains(loc, "://") {
			data, err = fetch.ReadLocal(loc)
		} else {
			data, err = e.Fetcher.Get(loc)
		}
		if err != nil {
			tried = append(tried, text.Safe(err.Error()))
			continue
		}
		claims, err := v.Verify(data, p.SHA256)
		if err != nil {
			verifyFailed = true
			tried = append(tried, text.Safe(fmt.Sprintf("%s: %v", loc, err)))
			continue
		}
		c.Put(p.SHA256, claims)
		return claims, loc, nil
	}
	if verifyFailed && e.rootName == "built-in" {
		tried = append(tried, "trusted root: built-in copy; run `apt-attest refresh` if a newer Sigstore key is needed")
	}
	return policy.Claims{}, "", errors.New(strings.Join(tried, "\n    "))
}

// Check decides one located package. It reports every reason for refusal to e.Out and
// returns false if the package must not be installed.
func (e *Engine) Check(p Package) bool {
	name := text.Safe(p.Name) + " " + text.Safe(p.Version) + " (" + text.Safe(p.File) + ")"
	if e.untraceable(p) {
		fmt.Fprintf(e.Out, "apt-attest: refusing %s: apt downloaded it, but no Packages index lists a file with its SHA256 %s, so its source cannot be checked against the policies' origins\n",
			name, p.SHA256)
		return false
	}
	pols := e.Covering(p)
	if len(pols) == 0 {
		return true
	}
	claims, from, err := e.Claims(p, true)
	if err != nil {
		fmt.Fprintf(e.Out, "apt-attest: refusing %s: no attestation that verifies\n  policy: %s\n  tried:\n    %s\n",
			name, policyNames(pols), err)
		return false
	}
	ok := true
	for _, pol := range pols {
		fails := policy.Failures(pol.Compare(claims, p.SHA256, p.Version, VersionLess))
		if len(fails) == 0 {
			continue
		}
		ok = false
		fmt.Fprintf(e.Out, "apt-attest: refusing %s: attestation does not match policy %s\n", name, text.Safe(pol.Path))
		for _, f := range fails {
			fmt.Fprintf(e.Out, "  %s: want %s, got %s\n", f.Field, text.Safe(f.Want), orNone(text.Safe(f.Got)))
		}
	}
	if ok {
		fmt.Fprintf(e.Out, "apt-attest: %s %s attested by %s (%s, %s)\n",
			text.Safe(p.Name), text.Safe(p.Version), text.Safe(claims.BuildSignerURI), policyNames(pols), text.Safe(from))
	}
	return ok
}

func policyNames(pols []*policy.Policy) string {
	var names []string
	for _, p := range pols {
		names = append(names, text.Safe(p.Path))
	}
	return strings.Join(names, ", ")
}

func orNone(s string) string {
	if s == "" {
		return "(none)"
	}
	return s
}

func FileSHA256(name string) (string, error) {
	f, err := os.Open(name)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", fmt.Errorf("%s: %w", name, err)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// VersionLess reports whether Debian version a sorts before b, by dpkg's rules.
func VersionLess(a, b string) (bool, error) {
	err := exec.Command("dpkg", "--compare-versions", a, "lt", b).Run()
	var exit *exec.ExitError
	switch {
	case err == nil:
		return true, nil
	case errors.As(err, &exit) && exit.ExitCode() == 1:
		return false, nil
	default:
		return false, fmt.Errorf("dpkg --compare-versions %q lt %q: %w", a, b, err)
	}
}

// ReadDeb reads a package file's name and version from its control file.
func ReadDeb(file string) (Package, error) {
	out, err := exec.Command("dpkg-deb", "--show", "--showformat", "${Package}\t${Version}", file).Output()
	if err != nil {
		return Package{}, fmt.Errorf("dpkg-deb --show %s: %w", file, err)
	}
	name, version, _ := strings.Cut(strings.TrimSpace(string(out)), "\t")
	return Package{Name: name, Version: version, File: file}, nil
}
