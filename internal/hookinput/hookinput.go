// Package hookinput parses what apt sends a DPkg::Pre-Install-Pkgs hook with protocol
// version 2 or 3, as described under Pre-Install-Pkgs in apt.conf(5).
package hookinput

import (
	"bufio"
	"fmt"
	"io"
	"net/url"
	"path/filepath"
	"strings"
)

type Input struct {
	Version int
	Config  map[string][]string
	Actions []Action
}

type Action struct {
	Package    string
	OldVersion string
	NewVersion string
	NewArch    string
	// File is the .deb being unpacked; empty for configure and remove actions.
	File string
}

func Parse(r io.Reader) (*Input, error) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), 16*1024*1024)
	if !sc.Scan() {
		return nil, fmt.Errorf("empty hook input: %v", sc.Err())
	}
	in := &Input{Config: map[string][]string{}}
	switch strings.TrimSpace(sc.Text()) {
	case "VERSION 2":
		in.Version = 2
	case "VERSION 3":
		in.Version = 3
	default:
		return nil, fmt.Errorf("hook input starts with %q, want VERSION 2 or 3: set DPkg::Tools::Options::<hook>::Version", sc.Text())
	}

	for sc.Scan() {
		line := sc.Text()
		if line == "" {
			break
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			return nil, fmt.Errorf("config line without '=': %q", line)
		}
		k = strings.ToLower(strings.TrimSuffix(unescape(k), "::"))
		in.Config[k] = append(in.Config[k], unescape(v))
	}

	fields := 5
	if in.Version == 3 {
		fields = 9
	}
	for sc.Scan() {
		line := sc.Text()
		if line == "" {
			continue
		}
		f, ok := splitFields(line, fields)
		if !ok {
			return nil, fmt.Errorf("package line has fewer than %d fields: %q", fields, line)
		}
		a := Action{Package: f[0], OldVersion: f[1]}
		if in.Version == 3 {
			a.NewVersion, a.NewArch = f[5], f[6]
		} else {
			a.NewVersion = f[3]
		}
		if act := f[fields-1]; act != "**CONFIGURE**" && act != "**REMOVE**" {
			a.File = act
		}
		in.Actions = append(in.Actions, a)
	}
	return in, sc.Err()
}

// Unpacks are the actions that install a .deb.
func (in *Input) Unpacks() []Action {
	var out []Action
	for _, a := range in.Actions {
		if a.File != "" {
			out = append(out, a)
		}
	}
	return out
}

// Get returns a config value; apt option names are case-insensitive.
func (in *Input) Get(key string) string {
	if v := in.Config[strings.ToLower(key)]; len(v) > 0 {
		return v[len(v)-1]
	}
	return ""
}

func unescape(s string) string {
	if !strings.Contains(s, "%") {
		return s
	}
	if u, err := url.PathUnescape(s); err == nil {
		return u
	}
	return s
}

// ArchivesDir is where apt keeps downloaded packages: Dir::Cache::archives, relative to
// Dir::Cache unless absolute, which is relative to Dir unless absolute.
func (in *Input) ArchivesDir() string {
	get := func(key, def string) string {
		if v := in.Get(key); v != "" {
			return v
		}
		return def
	}
	under := func(base, v string) string {
		if strings.HasPrefix(v, "/") {
			return filepath.Clean(v)
		}
		return filepath.Join(base, v)
	}
	cache := under(get("Dir", "/"), get("Dir::Cache", "var/cache/apt/"))
	return under(cache, get("Dir::Cache::archives", "archives/"))
}

// splitFields splits a package line into n fields. The last is a file name, which may
// itself contain spaces, so it is the rest of the line.
func splitFields(line string, n int) ([]string, bool) {
	f := make([]string, 0, n)
	rest := line
	for len(f) < n-1 {
		rest = strings.TrimLeft(rest, " ")
		field, after, ok := strings.Cut(rest, " ")
		if !ok || field == "" {
			return nil, false
		}
		f = append(f, field)
		rest = after
	}
	if rest == "" {
		return nil, false
	}
	return append(f, rest), true
}
