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
	"bytes"
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

// URL is where this source serves the package.
func (s Source) URL() (string, error) {
	base, err := url.Parse(strings.TrimRight(s.RepoURI, "/") + "/")
	if err != nil {
		return "", err
	}
	rel, err := url.Parse(s.Filename)
	if err != nil {
		return "", err
	}
	return base.ResolveReference(rel).String(), nil
}

type IndexTarget struct {
	RepoURI  string
	Filename string
}

// Want identifies a package to look up.
type Want struct {
	Package string
	SHA256  string
}

// Lookup returns, for each wanted SHA256, every source whose index lists a package of
// that name with that hash.
func Lookup(targets []IndexTarget, wants []Want) (map[string][]Source, error) {
	bySHA := map[string]string{}
	for _, w := range wants {
		bySHA[strings.ToLower(w.SHA256)] = w.Package
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
		err = scan(rc, func(pkg, filename, sha string) {
			sha = strings.ToLower(sha)
			if name, ok := bySHA[sha]; ok && name == pkg {
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

// scan fails on input that has content but no Package records, so an index it cannot
// read is an error rather than a source that carries nothing.
func scan(r io.Reader, record func(pkg, filename, sha string)) error {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 1024*1024), 16*1024*1024)
	var pkg, filename, sha string
	var records, nonEmpty int
	flush := func() {
		if pkg != "" {
			records++
		}
		if pkg != "" && filename != "" && sha != "" {
			record(pkg, filename, sha)
		}
		pkg, filename, sha = "", "", ""
	}
	for sc.Scan() {
		line := sc.Bytes()
		if len(bytes.TrimSpace(line)) > 0 {
			nonEmpty++
		}
		if len(line) == 0 {
			flush()
			continue
		}
		switch {
		case bytes.HasPrefix(line, []byte("Package:")):
			pkg = string(bytes.TrimSpace(line[len("Package:"):]))
		case bytes.HasPrefix(line, []byte("Filename:")):
			filename = string(bytes.TrimSpace(line[len("Filename:"):]))
		case bytes.HasPrefix(line, []byte("SHA256:")):
			sha = string(bytes.TrimSpace(line[len("SHA256:"):]))
		}
	}
	flush()
	if err := sc.Err(); err != nil {
		return err
	}
	if nonEmpty > 0 && records == 0 {
		return errors.New("not a Packages index: no Package records")
	}
	return nil
}
