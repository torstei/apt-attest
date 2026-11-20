package aptsource

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

const packagesA = `Package: pidvault
Version: 0.6.0-1
Architecture: amd64
Filename: pool/main/pidvault_0.6.0-1_amd64.deb
SHA256: B9A2A2189CB75B23262DCA925DFF67FE0D61AE8B2F220C2D039A10D992C8AE80
Description: x
 continuation line with SHA256: ffff

Package: other
Filename: pool/main/other.deb
SHA256: 1111
`

const packagesB = `Package: pidvault
Version: 0.6.0-1
Filename: pool/p/pidvault/pidvault_0.6.0-1_amd64.deb
SHA256: 2222

Package: renamed
Filename: pool/main/pidvault_0.6.0-1_amd64.deb
SHA256: b9a2a2189cb75b23262dca925dff67fe0d61ae8b2f220c2d039a10d992c8ae80
`

func TestLookupFindsTheSourceWithTheSameFile(t *testing.T) {
	dir := t.TempDir()
	a := filepath.Join(dir, "a_Packages")
	b := filepath.Join(dir, "b_Packages")
	os.WriteFile(a, []byte(packagesA), 0o644)
	os.WriteFile(b, []byte(packagesB), 0o644)
	targets := []IndexTarget{
		{RepoURI: "https://torstei.github.io/pidvault/", Filename: a},
		{RepoURI: "https://mirror.example/debian/", Filename: b},
		{RepoURI: "https://gone.example/", Filename: filepath.Join(dir, "missing_Packages")},
	}
	const sha = "b9a2a2189cb75b23262dca925dff67fe0d61ae8b2f220c2d039a10d992c8ae80"
	found, err := Lookup(targets, []string{sha})
	if err != nil {
		t.Fatal(err)
	}
	got := found[sha]
	if len(got) != 2 || got[0].RepoURI != "https://torstei.github.io/pidvault/" || got[1].RepoURI != "https://mirror.example/debian/" {
		t.Fatalf("both sources list a file with this hash, under any name: %+v", got)
	}
	u, err := got[0].URL()
	if err != nil || u != "https://torstei.github.io/pidvault/pool/main/pidvault_0.6.0-1_amd64.deb" {
		t.Fatalf("%q %v", u, err)
	}
}

// Whoever holds a repository's key writes its Packages file. apt reads field names in
// any case, normalizes package names and accepts repeated fields; each of these must
// still identify the source, or a package from a pinned origin goes unchecked.
func TestLenientIndexesStillIdentifyTheSource(t *testing.T) {
	const sha = "b9a2a2189cb75b23262dca925dff67fe0d61ae8b2f220c2d039a10d992c8ae80"
	const other = "1111111111111111111111111111111111111111111111111111111111111111"
	cases := map[string]string{
		"lowercase fields": "package: evil\nfilename: pool/evil.deb\nsha256: " + sha + "\n",
		"mixed case":       "PACKAGE: evil\nFileName: pool/evil.deb\nSha256: " + strings.ToUpper(sha) + "\n",
		"uppercase name":   "Package: EVIL\nFilename: pool/evil.deb\nSHA256: " + sha + "\n",
		"repeated hash":    "Package: evil\nFilename: pool/evil.deb\nSHA256: " + other + "\nSHA256: " + sha + "\n",
		"repeated hash 2":  "Package: evil\nFilename: pool/evil.deb\nSHA256: " + sha + "\nSHA256: " + other + "\n",
		"space before ':'": "Package: evil\nFilename : pool/evil.deb\nSHA256 : " + sha + "\n",
	}
	for name, index := range cases {
		t.Run(name, func(t *testing.T) {
			f := filepath.Join(t.TempDir(), "Packages")
			os.WriteFile(f, []byte("Package: decoy\nFilename: pool/d.deb\nSHA256: "+other+"\n\n"+index), 0o644)
			found, err := Lookup([]IndexTarget{{RepoURI: "https://r/", Filename: f}}, []string{sha})
			if err != nil || len(found[sha]) != 1 || found[sha][0].Filename != "pool/evil.deb" {
				t.Fatalf("%v %v", found, err)
			}
		})
	}
}

func TestURLStaysUnderTheSource(t *testing.T) {
	for _, file := range []string{
		"https://evil.example/x.deb",
		"//evil.example/x.deb",
		"../../other/x.deb",
		"/etc/shadow",
		"file:///etc/shadow",
		"pool/x.deb?u=1",
	} {
		if u, err := (Source{"https://r.example/debian/", file}).URL(); err == nil {
			t.Errorf("%q resolved to %s", file, u)
		}
	}
	if u, err := (Source{"file:/srv/repo/", "../../etc/shadow"}).URL(); err == nil {
		t.Errorf("file source escaped to %s", u)
	}
}

func TestURL(t *testing.T) {
	cases := []struct{ repo, file, want string }{
		{"http://archive.ubuntu.com/ubuntu/", "pool/main/a/a.deb", "http://archive.ubuntu.com/ubuntu/pool/main/a/a.deb"},
		{"http://localhost:8000", "pool/main/a.deb", "http://localhost:8000/pool/main/a.deb"},
		{"https://x.example/flat/", "./a.deb", "https://x.example/flat/a.deb"},
		{"file:/srv/repo/", "pool/a.deb", "file:///srv/repo/pool/a.deb"},
	}
	for _, c := range cases {
		if got, err := (Source{c.repo, c.file}).URL(); err != nil || got != c.want {
			t.Errorf("%s + %s = %q (%v), want %q", c.repo, c.file, got, err, c.want)
		}
	}
}

func TestCompressedIndexesAreRead(t *testing.T) {
	if _, err := os.Stat("/usr/lib/apt/apt-helper"); err != nil {
		t.Skip("no apt-helper")
	}
	dir := t.TempDir()
	plain := filepath.Join(dir, "a_Packages")
	os.WriteFile(plain, []byte(packagesA), 0o644)
	if out, err := exec.Command("gzip", "-k", plain).CombinedOutput(); err != nil {
		t.Fatalf("%v %s", err, out)
	}
	os.Remove(plain)
	const sha = "b9a2a2189cb75b23262dca925dff67fe0d61ae8b2f220c2d039a10d992c8ae80"
	for _, name := range []string{plain, plain + ".gz"} {
		found, err := Lookup([]IndexTarget{{RepoURI: "https://r/", Filename: name}}, []string{sha})
		if err != nil || len(found[sha]) != 1 {
			t.Errorf("%s: %v %v", name, found, err)
		}
	}
}

// An index that cannot be read must not look like a source that carries nothing:
// that would let a package from a pinned origin through.
func TestUnreadableIndexIsAnError(t *testing.T) {
	dir := t.TempDir()
	bogus := filepath.Join(dir, "x_Packages.lz4.unknown")
	os.WriteFile(bogus, []byte{0x04, 0x22, 0x4d, 0x18, 0xff, 0x00, 0x13}, 0o644)
	if _, err := Lookup([]IndexTarget{{RepoURI: "https://r/", Filename: bogus}}, []string{"ab"}); err == nil {
		t.Fatal("binary garbage read as an empty index")
	}
	empty := filepath.Join(dir, "empty_Packages")
	os.WriteFile(empty, nil, 0o644)
	if _, err := Lookup([]IndexTarget{{RepoURI: "https://r/", Filename: empty}}, []string{"ab"}); err != nil {
		t.Fatalf("empty index: %v", err)
	}
}
