// Package fetch downloads a Sigstore bundle. Where it comes from does not need to be
// trusted: the bundle is verified after download.
package fetch

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

const maxBundleSize = 16 << 20

var ErrNotFound = errors.New("not found")

type Fetcher struct {
	Client *http.Client
}

// New returns a fetcher that uses proxy, if set, for http and https, and the
// environment's proxy settings otherwise.
func New(proxy string) (*Fetcher, error) {
	proxyFunc := http.ProxyFromEnvironment
	if proxy != "" && proxy != "DIRECT" {
		u, err := url.Parse(proxy)
		if err != nil {
			return nil, fmt.Errorf("proxy %q: %w", proxy, err)
		}
		proxyFunc = http.ProxyURL(u)
	} else if proxy == "DIRECT" {
		proxyFunc = nil
	}
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.Proxy = proxyFunc
	return &Fetcher{Client: &http.Client{Transport: tr, Timeout: 60 * time.Second}}, nil
}

func (f *Fetcher) Get(rawURL string) ([]byte, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, err
	}
	switch u.Scheme {
	case "file", "copy":
		return readFile(u.Path)
	case "http", "https":
	default:
		return nil, fmt.Errorf("%s: unsupported URL scheme %q", rawURL, u.Scheme)
	}
	resp, err := f.Client.Get(rawURL)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusGone {
		return nil, fmt.Errorf("%s: %w (HTTP %d)", rawURL, ErrNotFound, resp.StatusCode)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s: HTTP %d", rawURL, resp.StatusCode)
	}
	return readLimited(resp.Body, rawURL)
}

func readFile(p string) ([]byte, error) {
	fh, err := os.Open(p)
	if os.IsNotExist(err) {
		return nil, fmt.Errorf("%s: %w", p, ErrNotFound)
	}
	if err != nil {
		return nil, err
	}
	defer fh.Close()
	return readLimited(fh, p)
}

func readLimited(r io.Reader, name string) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(r, maxBundleSize+1))
	if err != nil {
		return nil, fmt.Errorf("%s: %w", name, err)
	}
	if len(data) > maxBundleSize {
		return nil, fmt.Errorf("%s: larger than %d bytes", name, maxBundleSize)
	}
	return data, nil
}

// ReadLocal reads a bundle from a local path.
func ReadLocal(p string) ([]byte, error) { return readFile(p) }

// GitHubAttestations asks GitHub's attestation API for the bundles of attestations made
// in repository for a file with this SHA256. The API allows 60 requests an hour per IP
// address without a token.
func (f *Fetcher) GitHubAttestations(apiURL, repository, sha256Hex string) ([][]byte, error) {
	u := strings.TrimRight(apiURL, "/") + "/repos/" + repository + "/attestations/sha256:" + sha256Hex
	req, err := http.NewRequest(http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	resp, err := f.Client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	switch {
	case resp.StatusCode == http.StatusNotFound:
		return nil, fmt.Errorf("%s: %w", u, ErrNotFound)
	case (resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusTooManyRequests) &&
		resp.Header.Get("X-RateLimit-Remaining") == "0":
		reset := "later"
		if n, err := strconv.ParseInt(resp.Header.Get("X-RateLimit-Reset"), 10, 64); err == nil {
			reset = "at " + time.Unix(n, 0).Format("15:04")
		}
		return nil, fmt.Errorf("%s: GitHub's API limit of 60 requests an hour for this IP address is used up; it resets %s", u, reset)
	case resp.StatusCode != http.StatusOK:
		return nil, fmt.Errorf("%s: HTTP %d", u, resp.StatusCode)
	}
	data, err := readLimited(resp.Body, u)
	if err != nil {
		return nil, err
	}
	var body struct {
		Attestations []struct {
			Bundle json.RawMessage `json:"bundle"`
		} `json:"attestations"`
	}
	if err := json.Unmarshal(data, &body); err != nil {
		return nil, fmt.Errorf("%s: unexpected response", u)
	}
	var bundles [][]byte
	for _, a := range body.Attestations {
		if len(a.Bundle) > 0 && string(a.Bundle) != "null" {
			bundles = append(bundles, a.Bundle)
		}
	}
	if len(bundles) == 0 {
		return nil, fmt.Errorf("%s: %w", u, ErrNotFound)
	}
	return bundles, nil
}
