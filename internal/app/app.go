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
	Arch    string
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
	// GitHubURL and GitHubAPIURL are where release downloads and the attestation API
	// are; empty means github.com.
	GitHubURL    string
	GitHubAPIURL string

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

// A location is one place a package's bundle may be; get returns the bundles there.
type location struct {
	name string
	get  func() ([][]byte, error)
}

// locations lists where a package's bundle may be, nearest first: beside the file (an
// `apt install ./x.deb`), beside the package on each source that lists it, then for each
// covering policy its bundle_url and GitHub's attestation API. The last two come from
// the policy, never from the package, so the package cannot choose what is fetched.
func (e *Engine) locations(p Package, pols []*policy.Policy) []location {
	one := func(name string, read func(string) ([]byte, error)) location {
		return location{name, func() ([][]byte, error) {
			data, err := read(name)
			if err != nil {
				return nil, err
			}
			return [][]byte{data}, nil
		}}
	}
	if e.BundlePath != "" {
		return []location{one(e.BundlePath, fetch.ReadLocal)}
	}
	locs := []location{one(p.File+BundleSuffix, fetch.ReadLocal)}
	seen := map[string]bool{}
	for _, s := range p.Sources {
		if u, err := s.URL(); err == nil && !seen[u] {
			seen[u] = true
			locs = append(locs, one(u+BundleSuffix, e.Fetcher.Get))
		}
	}
	githubURL, apiURL := orDefault(e.GitHubURL, "https://github.com"), orDefault(e.GitHubAPIURL, "https://api.github.com")
	for _, pol := range pols {
		if u, err := pol.ExpandBundleURL(githubURL, p.Name, p.Version, p.Arch); err == nil && p.Arch != "" && !seen[u] {
			seen[u] = true
			locs = append(locs, one(u, e.Fetcher.Get))
		}
	}
	for _, pol := range pols {
		repo := pol.Identity.Repository
		if key := "api:" + strings.ToLower(repo); !seen[key] {
			seen[key] = true
			locs = append(locs, location{"GitHub attestations of " + repo, func() ([][]byte, error) {
				return e.Fetcher.GitHubAttestations(apiURL, repo, p.SHA256)
			}})
		}
	}
	return locs
}

func orDefault(s, def string) string {
	if s == "" {
		return def
	}
	return s
}

func (e *Engine) untraceable(p Package) bool {
	if e.ArchivesDir == "" || len(p.Sources) > 0 || !e.anyOrigins() {
		return false
	}
	return e.inArchives(p)
}

func (e *Engine) inArchives(p Package) bool {
	return e.ArchivesDir != "" && filepath.Dir(filepath.Clean(p.File)) == filepath.Clean(e.ArchivesDir)
}

// Satisfies reports whether claims meet every policy.
func Satisfies(claims policy.Claims, p Package, pols []*policy.Policy) bool {
	for _, pol := range pols {
		if len(policy.Failures(pol.Compare(claims, p.SHA256, p.Version, VersionLess))) > 0 {
			return false
		}
	}
	return true
}

// Claims finds the verified claims for a package: the first that satisfy every policy
// in pols, from the cache or from the locations in order. A location can hold several
// attestations, provenance and an SBOM say, so verifying is not enough to stop looking.
// If none satisfy them, it returns the first claims that verified, for reporting what
// did not match, or an error listing what was tried.
func (e *Engine) Claims(p Package, pols []*policy.Policy, useCache bool) (policy.Claims, string, error) {
	c := e.cache()
	if useCache {
		if claims, ok := c.Get(p.SHA256); ok && Satisfies(claims, p, pols) {
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
	var fallback *policy.Claims
	var fallbackFrom string
	verifyFailed := false
	for _, loc := range e.locations(p, pols) {
		bundles, err := loc.get()
		if err != nil {
			tried = append(tried, text.Safe(err.Error()))
			continue
		}
		for _, data := range bundles {
			claims, err := v.Verify(data, p.SHA256)
			if err != nil {
				verifyFailed = true
				tried = append(tried, text.Safe(fmt.Sprintf("%s: %v", loc.name, err)))
				continue
			}
			if Satisfies(claims, p, pols) {
				c.Put(p.SHA256, claims)
				return claims, loc.name, nil
			}
			if fallback == nil {
				fallback, fallbackFrom = &claims, loc.name
			}
		}
	}
	if fallback != nil {
		return *fallback, fallbackFrom, nil
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
	claims, from, err := e.Claims(p, pols, true)
	if err != nil {
		fmt.Fprintf(e.Out, "apt-attest: refusing %s: no attestation that verifies\n  policy: %s\n  tried:\n    %s\n",
			name, policyNames(pols), err)
		e.hint(p)
		return false
	}
	if !Satisfies(claims, p, pols) {
		for _, pol := range pols {
			fails := policy.Failures(pol.Compare(claims, p.SHA256, p.Version, VersionLess))
			if len(fails) == 0 {
				continue
			}
			fmt.Fprintf(e.Out, "apt-attest: refusing %s: attestation from %s does not match policy %s\n", name, text.Safe(from), text.Safe(pol.Path))
			for _, f := range fails {
				fmt.Fprintf(e.Out, "  %s: want %s, got %s\n", f.Field, text.Safe(f.Want), orNone(text.Safe(f.Got)))
			}
		}
		e.hint(p)
		return false
	}
	fmt.Fprintf(e.Out, "apt-attest: %s %s attested by %s (%s, %s)\n",
		text.Safe(p.Name), text.Safe(p.Version), text.Safe(claims.BuildSignerURI), policyNames(pols), text.Safe(from))
	return true
}

// hint tells someone installing a local file how to go on; a package apt downloaded has
// no such way out.
func (e *Engine) hint(p Package) {
	if e.inArchives(p) {
		return
	}
	f := text.Safe(p.File)
	fmt.Fprintf(e.Out, "  If you have its bundle, put it at %s%s and try again.\n  To install it without the check, knowing it is unverified: sudo dpkg -i %s\n", f, BundleSuffix, f)
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
	out, err := exec.Command("dpkg-deb", "--show", "--showformat", "${Package}\t${Version}\t${Architecture}", file).Output()
	if err != nil {
		return Package{}, fmt.Errorf("dpkg-deb --show %s: %w", file, err)
	}
	f := strings.SplitN(strings.TrimSpace(string(out)), "\t", 3)
	if len(f) != 3 {
		return Package{}, fmt.Errorf("dpkg-deb --show %s: unexpected output", file)
	}
	return Package{Name: f[0], Version: f[1], Arch: f[2], File: file}, nil
}
