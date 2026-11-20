// Package policy reads the attestation policies in /etc/apt/attestations.d and checks
// verified certificate claims against them.
package policy

import (
	"errors"
	"fmt"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/BurntSushi/toml"
)

const githubIssuer = "https://token.actions.githubusercontent.com"

var runners = map[string]bool{"github-hosted": true, "self-hosted": true}

type Match struct {
	Packages []string `toml:"packages"`
	Origins  []string `toml:"origins"`
}

type Identity struct {
	Issuer        string   `toml:"issuer"`
	Repository    string   `toml:"repository"`
	RepositoryID  int64    `toml:"repository_id"`
	OwnerID       int64    `toml:"owner_id"`
	Workflow      string   `toml:"workflow"`
	Refs          []string `toml:"refs"`
	Runner        string   `toml:"runner"`
	PredicateType string   `toml:"predicate_type"`
}

type Policy struct {
	Path       string   `toml:"-"`
	MinVersion string   `toml:"min_version"`
	Match      Match    `toml:"match"`
	Identity   Identity `toml:"identity"`

	origins []string
}

// Parse reads one policy. It rejects unknown keys and missing required keys, so a typo
// fails loudly instead of quietly weakening the check.
func Parse(name string, data []byte) (*Policy, error) {
	var p Policy
	md, err := toml.Decode(string(data), &p)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", name, err)
	}
	p.Path = name
	var problems []string
	if undecoded := md.Undecoded(); len(undecoded) > 0 {
		keys := make([]string, len(undecoded))
		for i, k := range undecoded {
			keys[i] = k.String()
		}
		problems = append(problems, "unknown keys: "+strings.Join(keys, ", "))
	}
	required := []string{
		"identity.issuer", "identity.repository", "identity.repository_id", "identity.owner_id",
		"identity.workflow", "identity.refs", "identity.runner", "identity.predicate_type",
	}
	for _, k := range required {
		if !md.IsDefined(strings.Split(k, ".")...) {
			problems = append(problems, "missing key "+k)
		}
	}
	problems = append(problems, p.validate()...)
	if len(problems) > 0 {
		return nil, fmt.Errorf("%s: %s", name, strings.Join(problems, "; "))
	}
	return &p, nil
}

func (p *Policy) validate() []string {
	var problems []string
	id := p.Identity
	if len(p.Match.Packages) == 0 && len(p.Match.Origins) == 0 {
		problems = append(problems, "match needs packages or origins")
	}
	for _, name := range p.Match.Packages {
		if name == "" || strings.ContainsAny(name, " \t:/") {
			problems = append(problems, fmt.Sprintf("match.packages: %q is not a package name", name))
		}
	}
	for _, o := range p.Match.Origins {
		norm, err := NormalizeOrigin(o)
		if err != nil {
			problems = append(problems, fmt.Sprintf("match.origins: %v", err))
			continue
		}
		p.origins = append(p.origins, norm)
	}
	if id.Issuer != "" && id.Issuer != githubIssuer {
		problems = append(problems, fmt.Sprintf("identity.issuer: only %s is supported", githubIssuer))
	}
	if parts := strings.Split(id.Repository, "/"); id.Repository != "" && (len(parts) != 2 || parts[0] == "" || parts[1] == "") {
		problems = append(problems, fmt.Sprintf("identity.repository: %q is not owner/name", id.Repository))
	}
	if id.RepositoryID < 0 || id.OwnerID < 0 || (id.Repository != "" && (id.RepositoryID == 0 || id.OwnerID == 0)) {
		problems = append(problems, "identity.repository_id and identity.owner_id must be positive")
	}
	if id.Workflow != "" && !strings.HasPrefix(id.Workflow, ".github/workflows/") {
		problems = append(problems, fmt.Sprintf("identity.workflow: %q is not under .github/workflows/", id.Workflow))
	}
	if id.Refs != nil && len(id.Refs) == 0 {
		problems = append(problems, "identity.refs is empty")
	}
	for _, r := range id.Refs {
		if _, err := path.Match(r, ""); err != nil || !strings.HasPrefix(r, "refs/") {
			problems = append(problems, fmt.Sprintf("identity.refs: %q is not a refs/... glob", r))
		}
	}
	if id.Runner != "" && !runners[id.Runner] {
		problems = append(problems, fmt.Sprintf("identity.runner: %q is neither github-hosted nor self-hosted", id.Runner))
	}
	return problems
}

// LoadDir reads every *.toml in dir. A missing directory means no policies; any file
// that fails to parse is an error, since skipping it would leave packages unchecked.
func LoadDir(dir string) ([]*Policy, error) {
	files, err := filepath.Glob(filepath.Join(dir, "*.toml"))
	if err != nil {
		return nil, err
	}
	sort.Strings(files)
	var policies []*Policy
	var errs []error
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		p, err := Parse(f, data)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		policies = append(policies, p)
	}
	return policies, errors.Join(errs...)
}

// NormalizeOrigin reduces an apt source base URL to a canonical form, so that the same
// repository compares equal however its URL is spelled: case of the host, a trailing
// slash, a default port, and http against https (the files are signed either way).
func NormalizeOrigin(s string) (string, error) {
	u, err := url.Parse(s)
	if err != nil || u.Scheme == "" || (u.Host == "" && u.Scheme != "file") {
		return "", fmt.Errorf("%q is not an absolute URL", s)
	}
	scheme := strings.ToLower(u.Scheme)
	host := strings.ToLower(u.Hostname())
	port := u.Port()
	if scheme == "http" || scheme == "https" {
		if port == "80" || port == "443" {
			port = ""
		}
		scheme = "http(s)"
	}
	if port != "" {
		host += ":" + port
	}
	return scheme + "://" + host + strings.TrimRight(u.Path, "/"), nil
}

// Matches reports whether the policy covers a package with this name, coming from any
// of these sources (base URLs, already normalized).
func (p *Policy) Matches(name string, origins []string) bool {
	for _, n := range p.Match.Packages {
		if n == name {
			return true
		}
	}
	for _, want := range p.origins {
		for _, got := range origins {
			if want == got {
				return true
			}
		}
	}
	return false
}

func (p *Policy) HasOrigins() bool { return len(p.origins) > 0 }

// NormalizedOrigins are the policy's origins as NormalizeOrigin returns them.
func (p *Policy) NormalizedOrigins() []string { return p.origins }

// Claims are the facts a verified attestation establishes about how a package was built.
type Claims struct {
	Issuer                          string    `json:"issuer"`
	SourceRepositoryURI             string    `json:"sourceRepositoryURI"`
	SourceRepositoryIdentifier      string    `json:"sourceRepositoryIdentifier"`
	SourceRepositoryOwnerIdentifier string    `json:"sourceRepositoryOwnerIdentifier"`
	BuildSignerURI                  string    `json:"buildSignerURI"`
	SourceRepositoryRef             string    `json:"sourceRepositoryRef"`
	RunnerEnvironment               string    `json:"runnerEnvironment"`
	PredicateType                   string    `json:"predicateType"`
	Subjects                        []Subject `json:"subjects"`
}

type Subject struct {
	Name   string `json:"name"`
	SHA256 string `json:"sha256"`
}

// Comparison is one policy expectation next to what the attestation says.
type Comparison struct {
	Field string
	Want  string
	Got   string
	OK    bool
}

// Compare checks claims for a package file with the given SHA256 and version against
// the policy. Every expectation is reported, so a caller can print all of them or only
// the failures.
func (p *Policy) Compare(c Claims, sha256Hex, version string, versionLess func(a, b string) (bool, error)) []Comparison {
	id := p.Identity
	repoURL := "https://github.com/" + id.Repository
	signerPath, signerRef, _ := strings.Cut(c.BuildSignerURI, "@")
	wantSigner := repoURL + "/" + id.Workflow

	cmp := []Comparison{
		{"issuer", id.Issuer, c.Issuer, c.Issuer == id.Issuer},
		{"repository", repoURL, c.SourceRepositoryURI, strings.EqualFold(c.SourceRepositoryURI, repoURL)},
		{"repository_id", strconv.FormatInt(id.RepositoryID, 10), c.SourceRepositoryIdentifier, c.SourceRepositoryIdentifier == strconv.FormatInt(id.RepositoryID, 10)},
		{"owner_id", strconv.FormatInt(id.OwnerID, 10), c.SourceRepositoryOwnerIdentifier, c.SourceRepositoryOwnerIdentifier == strconv.FormatInt(id.OwnerID, 10)},
		{"workflow", wantSigner, signerPath, sameSigner(signerPath, repoURL, id.Workflow)},
		{"refs", strings.Join(id.Refs, " | "), c.SourceRepositoryRef, matchesAny(id.Refs, c.SourceRepositoryRef)},
		{"workflow ref", strings.Join(id.Refs, " | "), signerRef, matchesAny(id.Refs, signerRef)},
		{"runner", id.Runner, c.RunnerEnvironment, c.RunnerEnvironment == id.Runner},
		{"predicate_type", id.PredicateType, c.PredicateType, c.PredicateType == id.PredicateType},
	}

	var subjects []string
	subjectOK := false
	for _, s := range c.Subjects {
		subjects = append(subjects, s.Name+" sha256:"+s.SHA256)
		if strings.EqualFold(s.SHA256, sha256Hex) {
			subjectOK = true
		}
	}
	cmp = append(cmp, Comparison{"subject", "sha256:" + sha256Hex, strings.Join(subjects, ", "), subjectOK})

	if p.MinVersion != "" {
		less, err := versionLess(version, p.MinVersion)
		got := version
		if err != nil {
			got = fmt.Sprintf("%s (%v)", version, err)
		}
		cmp = append(cmp, Comparison{"min_version", ">= " + p.MinVersion, got, err == nil && !less})
	}
	return cmp
}

// The repository part of a GitHub URL is case-insensitive; the workflow path is not.
func sameSigner(signerPath, repoURL, workflow string) bool {
	prefix := repoURL + "/"
	if len(signerPath) < len(prefix) || !strings.EqualFold(signerPath[:len(prefix)], prefix) {
		return false
	}
	return signerPath[len(prefix):] == workflow
}

// Globs use path.Match, so "*" does not cross a "/": refs/tags/v* matches refs/tags/v1.2
// but refs/heads/* does not match refs/heads/release/1.
func matchesAny(globs []string, ref string) bool {
	if ref == "" {
		return false
	}
	for _, g := range globs {
		if ok, _ := path.Match(g, ref); ok {
			return true
		}
	}
	return false
}

func Failures(cmp []Comparison) []Comparison {
	var out []Comparison
	for _, c := range cmp {
		if !c.OK {
			out = append(out, c)
		}
	}
	return out
}
