// Package trustroot provides Sigstore's trusted root: the copy last fetched through TUF,
// or the copy built into the binary until the first refresh.
package trustroot

import (
	_ "embed"
	"fmt"
	"os"
	"path/filepath"

	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/tuf"
)

//go:embed trusted_root.json
var embedded []byte

const fileName = "trusted_root.json"

// Load returns the refreshed copy in stateDir if there is a valid one, else the
// embedded copy. The string names which one was used.
func Load(stateDir string) (*root.TrustedRoot, string, error) {
	p := filepath.Join(stateDir, fileName)
	if data, err := os.ReadFile(p); err == nil {
		if tr, err := root.NewTrustedRootFromJSON(data); err == nil {
			return tr, p, nil
		}
	}
	tr, err := root.NewTrustedRootFromJSON(embedded)
	if err != nil {
		return nil, "", fmt.Errorf("built-in trusted root: %w", err)
	}
	return tr, "built-in", nil
}

// Refresh fetches the current trusted root from Sigstore's TUF repository, verified
// from the TUF root built into sigstore-go, and stores it in stateDir.
func Refresh(stateDir string) (string, error) {
	opts := tuf.DefaultOptions().WithCachePath(filepath.Join(stateDir, "tuf"))
	client, err := tuf.New(opts)
	if err != nil {
		return "", fmt.Errorf("TUF: %w", err)
	}
	data, err := client.GetTarget(fileName)
	if err != nil {
		return "", fmt.Errorf("TUF target %s: %w", fileName, err)
	}
	if _, err := root.NewTrustedRootFromJSON(data); err != nil {
		return "", fmt.Errorf("fetched %s: %w", fileName, err)
	}
	p := filepath.Join(stateDir, fileName)
	tmp := p + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return "", err
	}
	return p, os.Rename(tmp, p)
}
