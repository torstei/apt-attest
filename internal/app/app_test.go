package app

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/torstei/apt-attest/internal/aptsource"
	"github.com/torstei/apt-attest/internal/fetch"
	"github.com/torstei/apt-attest/internal/policy"
)

const pidvaultSHA256 = "b9a2a2189cb75b23262dca925dff67fe0d61ae8b2f220c2d039a10d992c8ae80"

func readFixture(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "attest", "testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// engine serves the fixture bundle from a fake apt repository whose index lists the
// packages given, all at pool/main/<name>.deb.
func engine(t *testing.T, serveBundle bool, index map[string]string) (*Engine, *bytes.Buffer, string) {
	t.Helper()
	bundle := readFixture(t, "pidvault_0.6.0-1_amd64.deb.sigstore.json")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if serveBundle && r.URL.Path == "/repo/pool/main/pidvault.deb.sigstore.json" {
			w.Write(bundle)
			return
		}
		http.NotFound(w, r)
	}))
	t.Cleanup(srv.Close)

	var lists strings.Builder
	for name, sha := range index {
		lists.WriteString("Package: " + name + "\nFilename: pool/main/" + name + ".deb\nSHA256: " + sha + "\n\n")
	}
	dir := t.TempDir()
	listFile := filepath.Join(dir, "Packages")
	os.WriteFile(listFile, []byte(lists.String()), 0o644)

	repo := srv.URL + "/repo/"
	p, err := policy.Parse("pidvault.toml", []byte(strings.Replace(string(readFixture(t, "pidvault.toml")),
		"https://torstei.github.io/pidvault", repo, 1)))
	if err != nil {
		t.Fatal(err)
	}
	f, _ := fetch.New("DIRECT")
	var out bytes.Buffer
	e := &Engine{
		Policies: []*policy.Policy{p},
		StateDir: filepath.Join(dir, "state"),
		Fetcher:  f,
		Out:      &out,
		IndexTargets: func() ([]aptsource.IndexTarget, error) {
			return []aptsource.IndexTarget{{RepoURI: repo, Filename: listFile}}, nil
		},
	}
	return e, &out, dir
}

func located(t *testing.T, e *Engine, p Package) Package {
	t.Helper()
	pkgs := []Package{p}
	if err := e.Locate(pkgs); err != nil {
		t.Fatal(err)
	}
	return pkgs[0]
}

func TestAttestedPackageFromTheRepositoryIsAccepted(t *testing.T) {
	e, out, _ := engine(t, true, map[string]string{"pidvault": pidvaultSHA256})
	p := located(t, e, Package{Name: "pidvault", Version: "0.6.0-1", File: "/nonexistent/pidvault.deb", SHA256: pidvaultSHA256})
	if !e.Check(p) {
		t.Fatal(out)
	}
	if !strings.Contains(out.String(), "attested by https://github.com/torstei/pidvault/.github/workflows/release.yml@refs/tags/v0.6.0") {
		t.Fatal(out)
	}
}

func TestVerifiedClaimsAreCachedForOfflineReinstall(t *testing.T) {
	e, out, _ := engine(t, true, map[string]string{"pidvault": pidvaultSHA256})
	p := located(t, e, Package{Name: "pidvault", Version: "0.6.0-1", File: "/nonexistent/pidvault.deb", SHA256: pidvaultSHA256})
	if !e.Check(p) {
		t.Fatal(out)
	}
	p.Sources = nil
	out.Reset()
	if !e.Check(p) || !strings.Contains(out.String(), "cache") {
		t.Fatalf("second check did not use the cache: %s", out)
	}

	e.Policies[0].Identity.Workflow = ".github/workflows/other.yml"
	out.Reset()
	if e.Check(p) {
		t.Fatal("a cached result outlived a policy change")
	}
}

func TestMissingBundleIsRefused(t *testing.T) {
	e, out, _ := engine(t, false, map[string]string{"pidvault": pidvaultSHA256})
	p := located(t, e, Package{Name: "pidvault", Version: "0.6.0-1", File: "/nonexistent/pidvault.deb", SHA256: pidvaultSHA256})
	if e.Check(p) {
		t.Fatal("installed without a bundle")
	}
	for _, want := range []string{"refusing pidvault 0.6.0-1", "pidvault.toml", "pool/main/pidvault.deb.sigstore.json: not found"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("message lacks %q:\n%s", want, out)
		}
	}
}

// A stolen repository key cannot ship an unattested package under a new name: the
// origin match still covers it.
func TestUnattestedPackageUnderANewNameFromTheOriginIsRefused(t *testing.T) {
	const evilSHA = "1111111111111111111111111111111111111111111111111111111111111111"
	e, out, _ := engine(t, true, map[string]string{"pidvault": pidvaultSHA256, "pidvault-helper": evilSHA})
	all := []Package{
		{Name: "pidvault-helper", Version: "1.0", File: "/nonexistent/h.deb", SHA256: evilSHA},
		{Name: "curl", Version: "8.0", File: "/nonexistent/curl.deb", SHA256: strings.Repeat("2", 64)},
	}
	cand := e.Candidates(all)
	if len(cand) != 2 {
		t.Fatalf("origin policies must consider every package, got %d", len(cand))
	}
	if err := e.Locate(cand); err != nil {
		t.Fatal(err)
	}
	if e.Check(cand[0]) {
		t.Fatal("unattested package from the origin was accepted")
	}
	if !e.Check(cand[1]) || strings.Contains(out.String(), "curl") {
		t.Fatalf("package from elsewhere was not left alone: %s", out)
	}
}

func TestLocalInstallUsesTheBundleBesideTheFile(t *testing.T) {
	e, out, dir := engine(t, false, map[string]string{})
	deb := filepath.Join(dir, "pidvault_0.6.0-1_amd64.deb")
	os.WriteFile(deb+BundleSuffix, readFixture(t, "pidvault_0.6.0-1_amd64.deb.sigstore.json"), 0o644)
	p := Package{Name: "pidvault", Version: "0.6.0-1", File: deb, SHA256: pidvaultSHA256}
	if !e.Check(p) {
		t.Fatal(out)
	}
}

func TestOnlyNamedPackagesAreCandidatesWithoutOriginPolicies(t *testing.T) {
	e, _, _ := engine(t, true, nil)
	e.Policies[0].Match.Origins = nil
	p, _ := policy.Parse("p.toml", []byte(strings.Replace(string(readFixture(t, "pidvault.toml")),
		`origins  = ["https://torstei.github.io/pidvault"]`, "", 1)))
	e.Policies = []*policy.Policy{p}
	cand := e.Candidates([]Package{{Name: "pidvault"}, {Name: "curl"}})
	if len(cand) != 1 || cand[0].Name != "pidvault" {
		t.Fatalf("%+v", cand)
	}
}
