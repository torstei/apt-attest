// Package aptsource finds which apt sources carry a given .deb, by its SHA256, and the
// URL each one serves it from.
//
// apt-get indextargets names every Packages index apt has downloaded together with its
// source's base URL. Reading those indexes for the record whose SHA256 equals the local
// file's identifies the exact copy being installed, even when several sources carry
// the same version with different contents. Neither step takes apt's lock, so this
// works from inside a dpkg hook.
package aptsource

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"os/exec"
	"strings"
)

type Source struct {
	RepoURI  string
	Filename string
}

// URL is where this source serves the package. Filename comes from the index, which
// whoever holds the repository's key writes, so the result must stay under the source.
func (s Source) URL() (string, error) {
	base, err := url.Parse(strings.TrimRight(s.RepoURI, "/") + "/")
	if err != nil {
		return "", err
	}
	rel, err := url.Parse(s.Filename)
	if err != nil {
		return "", err
	}
	u := base.ResolveReference(rel)
	if u.Scheme != base.Scheme || u.Host != base.Host || u.User != nil ||
		!strings.HasPrefix(u.Path, base.Path) || u.RawQuery != "" || u.Fragment != "" {
		return "", fmt.Errorf("Filename %q leads outside the source %s", s.Filename, s.RepoURI)
	}
	return u.String(), nil
}

type IndexTarget struct {
	RepoURI  string
	Filename string
}

// Lookup returns, for each wanted SHA256, every source whose index lists a file with
// that hash. It matches on the hash alone: apt normalizes package names, so comparing
// names could miss the very record apt installs from.
func Lookup(targets []IndexTarget, sha256s []string) (map[string][]Source, error) {
	want := map[string]bool{}
	for _, sha := range sha256s {
		want[strings.ToLower(sha)] = true
	}
	found := map[string][]Source{}
	for _, t := range targets {
		rc, err := openIndex(t.Filename)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return nil, err
		}
		err = scan(rc, func(filename, sha string) {
			sha = strings.ToLower(sha)
			if want[sha] {
				found[sha] = append(found[sha], Source{RepoURI: t.RepoURI, Filename: filename})
			}
		})
		if cerr := rc.Close(); err == nil {
			err = cerr
		}
		if err != nil {
			return nil, fmt.Errorf("%s: %w", t.Filename, err)
		}
	}
	return found, nil
}

// IndexTargets asks apt for every binary Packages index it has.
func IndexTargets() ([]IndexTarget, error) {
	out, err := exec.Command("apt-get", "indextargets", "--format", "$(REPO_URI)\t$(FILENAME)", "Created-By: Packages").Output()
	if err != nil {
		return nil, fmt.Errorf("apt-get indextargets: %w", err)
	}
	var targets []IndexTarget
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		repo, file, ok := strings.Cut(line, "\t")
		if ok && repo != "" && file != "" {
			targets = append(targets, IndexTarget{RepoURI: repo, Filename: file})
		}
	}
	return targets, nil
}

var compressedSuffixes = []string{".lz4", ".zst", ".gz", ".xz", ".bz2", ".lzma"}

// With Acquire::GzipIndexes apt keeps indexes compressed, and indextargets names either
// the compressed file or the uncompressed name; apt-helper reads every format apt does.
func openIndex(name string) (io.ReadCloser, error) {
	candidates := []string{name}
	for _, suf := range compressedSuffixes {
		candidates = append(candidates, name+suf)
	}
	for _, c := range candidates {
		if _, err := os.Stat(c); err != nil {
			continue
		}
		if !isCompressed(c) {
			return os.Open(c)
		}
		return catFile(c)
	}
	return nil, os.ErrNotExist
}

type helperOutput struct {
	io.Reader
	cmd  *exec.Cmd
	name string
}

// Close reports apt-helper's failure, so a truncated index is an error.
func (h *helperOutput) Close() error {
	_, _ = io.Copy(io.Discard, h.Reader)
	if err := h.cmd.Wait(); err != nil {
		return fmt.Errorf("apt-helper cat-file %s: %w", h.name, err)
	}
	return nil
}

func catFile(name string) (io.ReadCloser, error) {
	cmd := exec.Command("/usr/lib/apt/apt-helper", "cat-file", name)
	out, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("apt-helper cat-file %s: %w", name, err)
	}
	return &helperOutput{Reader: out, cmd: cmd, name: name}, nil
}

func isCompressed(name string) bool {
	for _, suf := range compressedSuffixes {
		if strings.HasSuffix(name, suf) {
			return true
		}
	}
	return false
}

// scan reports every (Filename, SHA256) pair of each record. Field names are matched
// case-insensitively and repeated fields all count, as apt is lenient in the same ways.
// Input that has content but no Package records is an error, so an index scan cannot
// read is never taken for a source that carries nothing.
func scan(r io.Reader, record func(filename, sha string)) error {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 1024*1024), 16*1024*1024)
	var hasPackage bool
	var filenames, shas []string
	var records, content int
	flush := func() {
		if hasPackage {
			records++
		}
		for _, f := range filenames {
			for _, h := range shas {
				record(f, h)
			}
		}
		hasPackage, filenames, shas = false, nil, nil
	}
	for sc.Scan() {
		line := sc.Text()
		if strings.TrimSpace(line) == "" {
			flush()
			continue
		}
		content++
		if line[0] == ' ' || line[0] == '\t' {
			continue
		}
		name, value, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		value = strings.TrimSpace(value)
		switch strings.ToLower(strings.TrimSpace(name)) {
		case "package":
			hasPackage = true
		case "filename":
			filenames = append(filenames, value)
		case "sha256":
			shas = append(shas, value)
		}
	}
	flush()
	if err := sc.Err(); err != nil {
		return err
	}
	if content > 0 && records == 0 {
		return errors.New("not a Packages index: no Package records")
	}
	return nil
}
