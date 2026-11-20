// Command apt-attest checks a package's Sigstore build provenance before apt installs it.
package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"text/tabwriter"

	"github.com/torstei/apt-attest/internal/app"
	"github.com/torstei/apt-attest/internal/fetch"
	"github.com/torstei/apt-attest/internal/hookinput"
	"github.com/torstei/apt-attest/internal/policy"
	"github.com/torstei/apt-attest/internal/trustroot"
)

var version = "dev"

const usage = `usage: apt-attest <command> [options]

commands:
  hook                 run as apt's DPkg::Pre-Install-Pkgs hook (protocol version 3 on stdin)
  check <file.deb>     check a package the way the hook does; exit 1 if it would be refused
  explain <file.deb>   print the attestation's claims next to each policy's expectations
  refresh              fetch Sigstore's current trusted root through TUF
  version              print the version

options:
  --policy-dir DIR     policies (default /etc/apt/attestations.d)
  --state-dir DIR      trusted root and cache of verified attestations (default /var/lib/apt-attest)
  --bundle FILE        check/explain: the bundle to use instead of looking for one
  --no-cache           check: verify the bundle even if this file has verified before
`

func main() {
	os.Exit(run(os.Args[1:], os.Stdin, os.Stderr))
}

func run(args []string, stdin io.Reader, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, usage)
		return 2
	}
	cmd := args[0]
	fs := flag.NewFlagSet(cmd, flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() { fmt.Fprint(stderr, usage) }
	policyDir := fs.String("policy-dir", "/etc/apt/attestations.d", "")
	stateDir := fs.String("state-dir", "/var/lib/apt-attest", "")
	bundlePath := fs.String("bundle", "", "")
	noCache := fs.Bool("no-cache", false, "")
	if err := fs.Parse(args[1:]); err != nil {
		return 2
	}

	switch cmd {
	case "version", "--version":
		fmt.Println(version)
		return 0
	case "help", "-h", "--help":
		fmt.Print(usage)
		return 0
	case "refresh":
		p, err := trustroot.Refresh(*stateDir)
		if err != nil {
			fmt.Fprintf(stderr, "apt-attest: refresh: %v\n", err)
			return 1
		}
		fmt.Fprintf(stderr, "apt-attest: trusted root updated in %s\n", p)
		return 0
	case "hook", "check", "explain":
	default:
		fmt.Fprintf(stderr, "apt-attest: unknown command %q\n%s", cmd, usage)
		return 2
	}

	policies, err := policy.LoadDir(*policyDir)
	if err != nil {
		fmt.Fprintf(stderr, "apt-attest: refusing to continue with a broken policy:\n  %v\n", strings.ReplaceAll(err.Error(), "\n", "\n  "))
		return 1
	}
	e := &app.Engine{Policies: policies, StateDir: *stateDir, Out: stderr, BundlePath: *bundlePath, NoCache: *noCache}

	switch cmd {
	case "hook":
		return hook(e, stdin, stderr)
	case "check", "explain":
		if fs.NArg() != 1 {
			fmt.Fprintf(stderr, "apt-attest %s: give one .deb file\n", cmd)
			return 2
		}
		if e.Fetcher, err = fetch.New(""); err != nil {
			fmt.Fprintf(stderr, "apt-attest: %v\n", err)
			return 2
		}
		if cmd == "check" {
			return check(e, fs.Arg(0), stderr)
		}
		return explain(e, fs.Arg(0))
	}
	return 2
}

func hook(e *app.Engine, stdin io.Reader, stderr io.Writer) int {
	r := stdin
	if fd := os.Getenv("APT_HOOK_INFO_FD"); fd != "" && fd != "0" {
		n, err := strconv.Atoi(fd)
		if err != nil {
			fmt.Fprintf(stderr, "apt-attest: APT_HOOK_INFO_FD=%q\n", fd)
			return 1
		}
		r = os.NewFile(uintptr(n), "apt-hook-info")
	}
	in, err := hookinput.Parse(r)
	if err != nil {
		fmt.Fprintf(stderr, "apt-attest: %v\n", err)
		return 1
	}
	if len(e.Policies) == 0 {
		return 0
	}

	proxy := in.Get("Acquire::https::Proxy")
	if proxy == "" {
		proxy = in.Get("Acquire::http::Proxy")
	}
	if e.Fetcher, err = fetch.New(proxy); err != nil {
		fmt.Fprintf(stderr, "apt-attest: %v\n", err)
		return 1
	}

	var pkgs []app.Package
	for _, a := range in.Unpacks() {
		pkgs = append(pkgs, app.Package{Name: a.Package, Version: a.NewVersion, File: a.File})
	}
	pkgs = e.Candidates(pkgs)
	if len(pkgs) == 0 {
		return 0
	}
	if err := e.Locate(pkgs); err != nil {
		fmt.Fprintf(stderr, "apt-attest: cannot tell where packages come from: %v\n", err)
		return 1
	}
	ok := true
	for _, p := range pkgs {
		if !e.Check(p) {
			ok = false
		}
	}
	if !ok {
		return 1
	}
	return 0
}

func locateOne(e *app.Engine, file string, stderr io.Writer) (app.Package, bool) {
	p, err := app.ReadDeb(file)
	if err != nil {
		fmt.Fprintf(stderr, "apt-attest: %v\n", err)
		return p, false
	}
	pkgs := []app.Package{p}
	if err := e.Locate(pkgs); err != nil {
		fmt.Fprintf(stderr, "apt-attest: %v\n", err)
		return p, false
	}
	return pkgs[0], true
}

func check(e *app.Engine, file string, stderr io.Writer) int {
	p, ok := locateOne(e, file, stderr)
	if !ok {
		return 2
	}
	if len(e.Covering(p)) == 0 {
		fmt.Fprintf(stderr, "apt-attest: %s %s is not covered by any policy in %d file(s); apt would install it unchecked\n",
			p.Name, p.Version, len(e.Policies))
		return 0
	}
	if !e.Check(p) {
		return 1
	}
	return 0
}

func explain(e *app.Engine, file string) int {
	p, ok := locateOne(e, file, os.Stderr)
	if !ok {
		return 2
	}
	fmt.Printf("package   %s %s\nfile      %s\nsha256    %s\n", p.Name, p.Version, p.File, p.SHA256)
	for _, s := range p.Sources {
		u, _ := s.URL()
		fmt.Printf("source    %s\n", u)
	}
	claims, from, err := e.Claims(p, false)
	if err != nil {
		fmt.Printf("\nno attestation that verifies:\n    %s\n", err)
		return 1
	}
	fmt.Printf("bundle    %s\n\n", from)

	w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(w, "claim\tvalue")
	for _, row := range [][2]string{
		{"issuer", claims.Issuer},
		{"sourceRepositoryURI", claims.SourceRepositoryURI},
		{"sourceRepositoryIdentifier", claims.SourceRepositoryIdentifier},
		{"sourceRepositoryOwnerIdentifier", claims.SourceRepositoryOwnerIdentifier},
		{"buildSignerURI", claims.BuildSignerURI},
		{"sourceRepositoryRef", claims.SourceRepositoryRef},
		{"runnerEnvironment", claims.RunnerEnvironment},
		{"predicateType", claims.PredicateType},
	} {
		fmt.Fprintf(w, "%s\t%s\n", row[0], row[1])
	}
	for _, s := range claims.Subjects {
		fmt.Fprintf(w, "subject\t%s  sha256:%s\n", s.Name, s.SHA256)
	}
	w.Flush()

	pols := e.Covering(p)
	if len(pols) == 0 {
		fmt.Printf("\nno policy covers %s; apt would install it unchecked\n", p.Name)
		return 0
	}
	status := 0
	for _, pol := range pols {
		fmt.Printf("\npolicy %s\n", pol.Path)
		w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
		fmt.Fprintln(w, "\tfield\twant\tgot")
		for _, c := range pol.Compare(claims, p.SHA256, p.Version, app.VersionLess) {
			mark := "ok"
			if !c.OK {
				mark, status = "FAIL", 1
			}
			fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", mark, c.Field, c.Want, c.Got)
		}
		w.Flush()
	}
	return status
}
