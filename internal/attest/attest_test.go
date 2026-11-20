package attest

import (
	"os"
	"strings"
	"testing"

	"github.com/sigstore/sigstore-go/pkg/root"

	"github.com/torstei/apt-attest/internal/policy"
	"github.com/torstei/apt-attest/internal/trustroot"
)

const (
	pidvaultSHA256 = "b9a2a2189cb75b23262dca925dff67fe0d61ae8b2f220c2d039a10d992c8ae80"
	otherSHA256    = "0000000000000000000000000000000000000000000000000000000000000000"
)

func verifier(t *testing.T) *Verifier {
	t.Helper()
	tr, _, err := trustroot.Load(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	v, err := NewVerifier(tr)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func fixture(t *testing.T) []byte {
	t.Helper()
	data, err := os.ReadFile("testdata/pidvault_0.6.0-1_amd64.deb.sigstore.json")
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func pidvaultPolicy(t *testing.T, edit func(string) string) *policy.Policy {
	t.Helper()
	data, err := os.ReadFile("testdata/pidvault.toml")
	if err != nil {
		t.Fatal(err)
	}
	p, err := policy.Parse("pidvault.toml", []byte(edit(string(data))))
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func noVersionCheck(a, b string) (bool, error) { return false, nil }

func TestPidvaultReleasePassesItsPolicy(t *testing.T) {
	claims, err := verifier(t).Verify(fixture(t), pidvaultSHA256)
	if err != nil {
		t.Fatal(err)
	}
	p := pidvaultPolicy(t, func(s string) string { return s })
	if fails := policy.Failures(p.Compare(claims, pidvaultSHA256, "0.6.0-1", noVersionCheck)); len(fails) > 0 {
		t.Fatalf("unexpected failures: %+v", fails)
	}
}

// Each policy change must make the real pidvault 0.6.0 attestation fail on exactly
// the field that was changed.
func TestPidvaultReleaseFailsAChangedPolicy(t *testing.T) {
	claims, err := verifier(t).Verify(fixture(t), pidvaultSHA256)
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name, from, to string
		fields         []string
	}{
		{"workflow", `".github/workflows/release.yml"`, `".github/workflows/ci.yml"`, []string{"workflow"}},
		{"ref", `["refs/tags/v*"]`, `["refs/heads/main"]`, []string{"refs", "workflow ref"}},
		{"repository id", `1431302070`, `1431302071`, []string{"repository_id"}},
		{"owner id", `owner_id       = 1751971`, `owner_id       = 1751972`, []string{"owner_id"}},
		{"repository", `"torstei/pidvault"`, `"torstei/pidvault2"`, []string{"repository", "workflow"}},
		{"runner", `"github-hosted"`, `"self-hosted"`, []string{"runner"}},
		{"predicate type", `"https://slsa.dev/provenance/v1"`, `"https://spdx.dev/Document/v2.3"`, []string{"predicate_type"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p := pidvaultPolicy(t, func(s string) string {
				if !strings.Contains(s, c.from) {
					t.Fatalf("policy has no %s", c.from)
				}
				return strings.Replace(s, c.from, c.to, 1)
			})
			assertFails(t, p.Compare(claims, pidvaultSHA256, "0.6.0-1", noVersionCheck), c.fields)
		})
	}
}

func assertFails(t *testing.T, cmp []policy.Comparison, want []string) {
	t.Helper()
	var got []string
	for _, f := range policy.Failures(cmp) {
		got = append(got, f.Field)
	}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("failed fields %v, want %v", got, want)
	}
}

func TestBundleForAnotherFileIsRejected(t *testing.T) {
	_, err := verifier(t).Verify(fixture(t), otherSHA256)
	if err == nil || !strings.Contains(err.Error(), "bundle is for pidvault_0.6.0-1_amd64.deb") {
		t.Fatalf("got %v", err)
	}
}

func TestTamperedStatementIsRejected(t *testing.T) {
	data := strings.Replace(string(fixture(t)), `"payload":"`, `"payload":"e30K`, 1)
	if data == string(fixture(t)) {
		t.Fatal("could not find the DSSE payload to tamper with")
	}
	if _, err := verifier(t).Verify([]byte(data), pidvaultSHA256); err == nil {
		t.Fatal("tampered bundle verified")
	}
}

func TestUntrustedRootIsRejected(t *testing.T) {
	empty, err := root.NewTrustedRoot(root.TrustedRootMediaType01, nil, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	v, err := NewVerifier(empty)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := v.Verify(fixture(t), pidvaultSHA256); err == nil {
		t.Fatal("verified against an empty trusted root")
	}
}

func TestGarbageIsRejected(t *testing.T) {
	for _, data := range []string{"", "{}", "not json", `{"mediaType":"application/vnd.dev.sigstore.bundle.v0.3+json"}`} {
		if _, err := verifier(t).Verify([]byte(data), pidvaultSHA256); err == nil {
			t.Fatalf("%q verified", data)
		}
	}
}
