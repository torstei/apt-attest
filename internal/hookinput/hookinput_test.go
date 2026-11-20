package hookinput

import (
	"strings"
	"testing"
)

const v3 = `VERSION 3
APT::Architecture=amd64
Acquire::http::Proxy=http://proxy%3a3128
DPkg::Pre-Install-Pkgs::=/usr/sbin/dpkg-preconfigure --apt
DPkg::Pre-Install-Pkgs::=/usr/bin/apt-attest hook
Dir::Etc=etc/apt

pidvault - - none < 0.6.0-1 amd64 same /var/cache/apt/archives/pidvault_0.6.0-1_amd64.deb
libfoo 1.0 amd64 same < 1.1 amd64 same /tmp/a%20b.deb
oldpkg 1.0 amd64 none > - - none **REMOVE**
pidvault - - none < 0.6.0-1 amd64 same **CONFIGURE**
`

func TestParseV3(t *testing.T) {
	in, err := Parse(strings.NewReader(v3))
	if err != nil {
		t.Fatal(err)
	}
	if in.Version != 3 || len(in.Actions) != 4 {
		t.Fatalf("%+v", in)
	}
	u := in.Unpacks()
	if len(u) != 2 {
		t.Fatalf("unpacks: %+v", u)
	}
	if u[0] != (Action{Package: "pidvault", OldVersion: "-", NewVersion: "0.6.0-1", NewArch: "amd64", File: "/var/cache/apt/archives/pidvault_0.6.0-1_amd64.deb"}) {
		t.Fatalf("%+v", u[0])
	}
	if u[1].File != "/tmp/a%20b.deb" {
		t.Fatalf("file names are not escaped: %q", u[1].File)
	}
	if got := in.Get("acquire::HTTP::proxy"); got != "http://proxy:3128" {
		t.Fatalf("proxy %q", got)
	}
	if got := in.Config["dpkg::pre-install-pkgs"]; len(got) != 2 {
		t.Fatalf("list %v", got)
	}
}

func TestParseV2(t *testing.T) {
	in, err := Parse(strings.NewReader("VERSION 2\nA=b\n\npidvault - < 0.6.0-1 /x/pidvault.deb\n"))
	if err != nil {
		t.Fatal(err)
	}
	if u := in.Unpacks(); len(u) != 1 || u[0].NewVersion != "0.6.0-1" || u[0].File != "/x/pidvault.deb" {
		t.Fatalf("%+v", u)
	}
}

func TestRejects(t *testing.T) {
	for _, s := range []string{
		"",
		"/var/cache/apt/archives/x.deb\n",
		"VERSION 3\n\npidvault - < 0.6.0-1 /x.deb\n",
		"VERSION 3\nnot a config line\n\n",
	} {
		if _, err := Parse(strings.NewReader(s)); err == nil {
			t.Errorf("accepted %q", s)
		}
	}
}
