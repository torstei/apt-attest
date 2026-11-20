package policy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const valid = `
[match]
packages = ["pidvault"]
origins  = ["https://torstei.github.io/pidvault"]

[identity]
issuer         = "https://token.actions.githubusercontent.com"
repository     = "torstei/pidvault"
repository_id  = 1431302070
owner_id       = 1751971
workflow       = ".github/workflows/release.yml"
refs           = ["refs/tags/v*"]
runner         = "github-hosted"
predicate_type = "https://slsa.dev/provenance/v1"
`

func mustParse(t *testing.T, s string) *Policy {
	t.Helper()
	p, err := Parse("test.toml", []byte(s))
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func parseErr(t *testing.T, s, want string) {
	t.Helper()
	_, err := Parse("test.toml", []byte(s))
	if err == nil || !strings.Contains(err.Error(), want) {
		t.Fatalf("got error %v, want one containing %q", err, want)
	}
}

func TestValidPolicyParses(t *testing.T) {
	p := mustParse(t, valid)
	if p.Identity.RepositoryID != 1431302070 || p.Identity.Refs[0] != "refs/tags/v*" {
		t.Fatalf("%+v", p)
	}
}

func TestUnknownKeysAreRejected(t *testing.T) {
	parseErr(t, strings.Replace(valid, "workflow ", "workflows", 1), "unknown keys: identity.workflows")
	parseErr(t, valid+"\n[extra]\nx = 1\n", "unknown keys: extra")
	parseErr(t, "min_versoin = \"1\"\n"+valid, "unknown keys: min_versoin")
	parseErr(t, strings.Replace(valid, "[match]", "[match]\nname = \"x\"", 1), "unknown keys: match.name")
}

func TestMissingKeysAreRejected(t *testing.T) {
	for _, key := range []string{"issuer", "repository", "repository_id", "owner_id", "workflow", "refs", "runner", "predicate_type"} {
		var kept []string
		for _, line := range strings.Split(valid, "\n") {
			if !strings.HasPrefix(line, key+" ") {
				kept = append(kept, line)
			}
		}
		parseErr(t, strings.Join(kept, "\n"), "missing key identity."+key)
	}
	parseErr(t, strings.NewReplacer(`packages = ["pidvault"]`, "", `origins  = ["https://torstei.github.io/pidvault"]`, "").Replace(valid),
		"match needs packages or origins")
}

func TestBadValuesAreRejected(t *testing.T) {
	cases := map[string][2]string{
		"issuer":        {`"https://token.actions.githubusercontent.com"`, `"https://accounts.google.com"`},
		"repository":    {`"torstei/pidvault"`, `"pidvault"`},
		"repository_id": {`1431302070`, `0`},
		"workflow":      {`".github/workflows/release.yml"`, `"release.yml"`},
		"refs glob":     {`["refs/tags/v*"]`, `["refs/tags/v["]`},
		"refs prefix":   {`["refs/tags/v*"]`, `["v*"]`},
		"refs empty":    {`["refs/tags/v*"]`, `[]`},
		"runner":        {`"github-hosted"`, `"hosted"`},
		"origin":        {`"https://torstei.github.io/pidvault"`, `"torstei.github.io/pidvault"`},
		"package":       {`["pidvault"]`, `["pid vault"]`},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := Parse("t.toml", []byte(strings.Replace(valid, c[0], c[1], 1))); err == nil {
				t.Fatalf("%s accepted", c[1])
			}
		})
	}
}

func TestRefGlobs(t *testing.T) {
	cases := []struct {
		globs []string
		ref   string
		ok    bool
	}{
		{[]string{"refs/tags/v*"}, "refs/tags/v0.6.0", true},
		{[]string{"refs/tags/v*"}, "refs/tags/0.6.0", false},
		{[]string{"refs/tags/v*"}, "refs/heads/v1", false},
		{[]string{"refs/heads/*"}, "refs/heads/release/1", false},
		{[]string{"refs/heads/main", "refs/tags/v*"}, "refs/heads/main", true},
		{[]string{"refs/tags/v[0-9]*"}, "refs/tags/vx", false},
		{[]string{"refs/tags/*"}, "", false},
	}
	for _, c := range cases {
		if got := matchesAny(c.globs, c.ref); got != c.ok {
			t.Errorf("matchesAny(%v, %q) = %v, want %v", c.globs, c.ref, got, c.ok)
		}
	}
}

func TestMatchingByNameAndOrigin(t *testing.T) {
	byName := mustParse(t, strings.Replace(valid, `origins  = ["https://torstei.github.io/pidvault"]`, "", 1))
	byOrigin := mustParse(t, strings.Replace(valid, `packages = ["pidvault"]`, "", 1))
	origin := mustNormalize(t, "https://torstei.github.io/pidvault/")
	elsewhere := mustNormalize(t, "http://archive.ubuntu.com/ubuntu/")

	cases := []struct {
		p       *Policy
		name    string
		origins []string
		want    bool
	}{
		{byName, "pidvault", nil, true},
		{byName, "pidvault", []string{elsewhere}, true},
		{byName, "evil", []string{origin}, false},
		{byOrigin, "evil", []string{origin}, true},
		{byOrigin, "pidvault", []string{elsewhere}, false},
		{byOrigin, "pidvault", nil, false},
		{byOrigin, "anything", []string{elsewhere, origin}, true},
	}
	for _, c := range cases {
		if got := c.p.Matches(c.name, c.origins); got != c.want {
			t.Errorf("Matches(%q, %v) = %v, want %v (packages %v, origins %v)", c.name, c.origins, got, c.want, c.p.Match.Packages, c.p.Match.Origins)
		}
	}
}

func mustNormalize(t *testing.T, s string) string {
	t.Helper()
	n, err := NormalizeOrigin(s)
	if err != nil {
		t.Fatal(err)
	}
	return n
}

func TestNormalizeOrigin(t *testing.T) {
	cases := map[string]string{
		"https://Torstei.GitHub.io/pidvault/":    "http(s)://torstei.github.io/pidvault",
		"https://torstei.github.io/pidvault":     "http(s)://torstei.github.io/pidvault",
		"http://torstei.github.io/pidvault":      "http(s)://torstei.github.io/pidvault",
		"https://torstei.github.io:443/pidvault": "http(s)://torstei.github.io/pidvault",
		"http://torstei.github.io:80/pidvault/":  "http(s)://torstei.github.io/pidvault",
		"http://127.0.0.1:8001":                  "http(s)://127.0.0.1:8001",
		"file:/srv/repo/":                        "file:///srv/repo",
		"file:///srv/repo":                       "file:///srv/repo",
	}
	for in, want := range cases {
		if got := mustNormalize(t, in); got != want {
			t.Errorf("NormalizeOrigin(%q) = %q, want %q", in, got, want)
		}
	}
}

var goodClaims = Claims{
	Issuer:                          "https://token.actions.githubusercontent.com",
	SourceRepositoryURI:             "https://github.com/torstei/pidvault",
	SourceRepositoryIdentifier:      "1431302070",
	SourceRepositoryOwnerIdentifier: "1751971",
	BuildSignerURI:                  "https://github.com/torstei/pidvault/.github/workflows/release.yml@refs/tags/v0.6.0",
	SourceRepositoryRef:             "refs/tags/v0.6.0",
	RunnerEnvironment:               "github-hosted",
	PredicateType:                   "https://slsa.dev/provenance/v1",
	Subjects:                        []Subject{{"pidvault_0.6.0-1_amd64.deb", "abc"}},
}

func lexLess(a, b string) (bool, error) { return a < b, nil }

func failedFields(cmp []Comparison) string {
	var out []string
	for _, f := range Failures(cmp) {
		out = append(out, f.Field)
	}
	return strings.Join(out, ",")
}

func TestCompare(t *testing.T) {
	p := mustParse(t, valid)
	if f := failedFields(p.Compare(goodClaims, "abc", "0.6.0-1", lexLess)); f != "" {
		t.Fatalf("good claims failed: %s", f)
	}

	upper := goodClaims
	upper.SourceRepositoryURI = "https://github.com/Torstei/PidVault"
	upper.BuildSignerURI = "https://github.com/Torstei/PidVault/.github/workflows/release.yml@refs/tags/v0.6.0"
	if f := failedFields(p.Compare(upper, "abc", "0.6.0-1", lexLess)); f != "" {
		t.Fatalf("repository case should not matter: %s", f)
	}

	cases := map[string]struct {
		edit func(*Claims)
		want string
	}{
		"workflow case": {func(c *Claims) { c.BuildSignerURI = strings.Replace(c.BuildSignerURI, "release.yml", "Release.yml", 1) }, "workflow"},
		"reusable workflow": {func(c *Claims) {
			c.BuildSignerURI = "https://github.com/evil/x/.github/workflows/release.yml@refs/tags/v0.6.0"
		}, "workflow"},
		"signer on a branch": {func(c *Claims) {
			c.BuildSignerURI = strings.Replace(c.BuildSignerURI, "refs/tags/v0.6.0", "refs/heads/main", 1)
		}, "workflow ref"},
		"no signer ref": {func(c *Claims) { c.BuildSignerURI = strings.Split(c.BuildSignerURI, "@")[0] }, "workflow ref"},
		"workflow prefix": {func(c *Claims) {
			c.BuildSignerURI = strings.Replace(c.BuildSignerURI, "release.yml", "release.yml.evil", 1)
		}, "workflow"},
		"issuer":     {func(c *Claims) { c.Issuer = "https://accounts.google.com" }, "issuer"},
		"no subject": {func(c *Claims) { c.Subjects = nil }, "subject"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			claims := goodClaims
			c.edit(&claims)
			if f := failedFields(p.Compare(claims, "abc", "0.6.0-1", lexLess)); f != c.want {
				t.Fatalf("failed %q, want %q", f, c.want)
			}
		})
	}
	if f := failedFields(p.Compare(goodClaims, "def", "0.6.0-1", lexLess)); f != "subject" {
		t.Fatalf("other digest: failed %q", f)
	}
}

func TestMinVersion(t *testing.T) {
	p := mustParse(t, "min_version = \"0.6.0-1\"\n"+valid)
	if f := failedFields(p.Compare(goodClaims, "abc", "0.5.9-1", lexLess)); f != "min_version" {
		t.Fatalf("older version: failed %q", f)
	}
	if f := failedFields(p.Compare(goodClaims, "abc", "0.6.0-1", lexLess)); f != "" {
		t.Fatalf("same version: failed %q", f)
	}
}

func TestLoadDir(t *testing.T) {
	dir := t.TempDir()
	if ps, err := LoadDir(filepath.Join(dir, "missing")); err != nil || len(ps) != 0 {
		t.Fatalf("missing dir: %v %v", ps, err)
	}
	write := func(name, s string) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(s), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("a.toml", valid)
	write("notes.txt", "ignored")
	if ps, err := LoadDir(dir); err != nil || len(ps) != 1 {
		t.Fatalf("got %d policies, %v", len(ps), err)
	}
	write("b.toml", "[match]\npackages = [\"x\"]\n")
	if _, err := LoadDir(dir); err == nil || !strings.Contains(err.Error(), "b.toml") {
		t.Fatalf("broken policy: %v", err)
	}
}

func TestBundleURL(t *testing.T) {
	p := mustParse(t, valid)
	cases := []struct{ pkg, version, arch, want string }{
		{"pidvault", "0.6.0-1", "amd64", "https://github.com/torstei/pidvault/releases/download/v0.6.0/pidvault_0.6.0-1_amd64.deb.sigstore.json"},
		{"pidvault", "2:1.0~rc1-3+b1", "arm64", "https://github.com/torstei/pidvault/releases/download/v1.0~rc1/pidvault_1.0~rc1-3+b1_arm64.deb.sigstore.json"},
		{"pidvault", "1.0", "all", "https://github.com/torstei/pidvault/releases/download/v1.0/pidvault_1.0_all.deb.sigstore.json"},
		{"x/../../evil", "1.0?a=b#c", "amd64", "https://github.com/torstei/pidvault/releases/download/v1.0%3Fa=b%23c/x%2F..%2F..%2Fevil_1.0%3Fa=b%23c_amd64.deb.sigstore.json"},
	}
	for _, c := range cases {
		got, err := p.ExpandBundleURL("https://github.com/", c.pkg, c.version, c.arch)
		if err != nil || got != c.want {
			t.Errorf("%s %s %s:\n got %s (%v)\nwant %s", c.pkg, c.version, c.arch, got, err, c.want)
		}
	}

	custom := mustParse(t, `bundle_url = "https://downloads.example/{package}/{upstream_version}/{package}_{version}_{arch}.deb.sigstore.json"`+"\n"+valid)
	if got, _ := custom.ExpandBundleURL("https://github.com", "pidvault", "0.6.0-1", "amd64"); got != "https://downloads.example/pidvault/0.6.0/pidvault_0.6.0-1_amd64.deb.sigstore.json" {
		t.Errorf("custom: %s", got)
	}

	for _, bad := range []string{
		`"ftp://x/{package}"`,
		`"https://{package}.example/x"`,
		`"https://example/{name}"`,
		`"/relative/{package}"`,
	} {
		if _, err := Parse("t.toml", []byte("bundle_url = "+bad+"\n"+valid)); err == nil {
			t.Errorf("bundle_url %s accepted", bad)
		}
	}
}
