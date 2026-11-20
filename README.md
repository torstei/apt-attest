# apt-attest

An APT hook that checks build provenance before dpkg unpacks a package. For each package
a policy covers, it verifies the package's Sigstore attestation and checks that it was
made by the build the policy expects, for example "the `release.yml` workflow of
`torstei/pidvault`, on a `v*` tag, on a GitHub-hosted runner". A covered package that
fails the check is not installed. Packages no policy covers are left alone.

## Why

apt checks that a package is byte for byte what the holder of the repository's signing
key published. It does not check how or where the package was built. Projects that build
in GitHub Actions can attest that (SLSA provenance, signed with Sigstore, logged in
Rekor), but the attestation is only checked if someone runs `gh attestation verify` by
hand.

With apt-attest, a stolen repository signing key is no longer enough to ship a package to
users who have a policy for that repository. The attacker would also need an attestation
from the pinned workflow and ref, and every such attestation is in Rekor's public log.

apt-attest adds to apt's checks and replaces none of them. Sources stay ordinary
`deb [signed-by=…] https://…` lines; apt verifies signatures and hashes as usual.

## What it checks

For each package being unpacked that a policy covers:

1. The bundle's certificate chains to Sigstore's Fulcio root and was valid when the
   signature was made, according to the Rekor entry's integrated time or a signed
   timestamp.
2. The Rekor entry is genuine: its inclusion proof and signed checkpoint verify against
   the log's key.
3. The DSSE signature over the in-toto statement verifies with the certificate's key.
4. The statement's subject digest equals the `.deb`'s SHA256, its `predicateType` is
   the policy's, and the certificate's claims match the policy.

Steps 1 to 3 are [sigstore-go](https://github.com/sigstore/sigstore-go), the library
behind `gh attestation verify` and `cosign`. Verification is offline, against Sigstore's
trusted root.

## Install

Download the `.deb` for your architecture and its bundle from the
[releases](https://github.com/torstei/apt-attest/releases), check it, and install it:

```sh
gh attestation verify apt-attest_*_amd64.deb --repo torstei/apt-attest
sudo apt install ./apt-attest_*_amd64.deb
```

It installs:

- `/usr/bin/apt-attest`
- `/etc/apt/apt.conf.d/20apt-attest`, which registers the hook
- `/etc/apt/attestations.d/`, empty: nothing is checked until you add a policy
- example policies in `/usr/share/doc/apt-attest/examples/`

## Policies

One TOML file per policy in `/etc/apt/attestations.d/`:

```toml
# /etc/apt/attestations.d/pidvault.toml
[match]
packages = ["pidvault"]
origins  = ["https://torstei.github.io/pidvault"]

[identity]
issuer         = "https://token.actions.githubusercontent.com"
repository     = "torstei/pidvault"
repository_id  = 1431302070
owner_id       = 1751971
workflow       = ".github/workflows/release.yml"
refs           = ["refs/tags/v*"]
runner         = "github-hosted"
predicate_type = "https://slsa.dev/provenance/v1"
```

**Which packages it covers.** A policy covers a package if the package's name is in
`packages`, **or** the package comes from a source in `origins`; at least one of the two
is required.

- Matching by name requires the attestation wherever the package comes from.
- Matching by origin requires it for everything from that source, so a stolen key cannot
  ship an unattested package under a new name. An origin is the URL in the `deb` line,
  and matches whatever apt shows as that source, ignoring a trailing slash.

If several policies cover a package, it must satisfy all of them.

**What the attestation must say.** Every `[identity]` key is required. A policy file with
a missing key, an unknown key or a bad value stops every install until it is fixed, so a
typo cannot weaken the check.

`issuer` decides how the other keys are read. The keys are named after Sigstore's
certificate claims, which every CI system that Sigstore issues certificates to fills
in; GitHub Actions is the only issuer supported so far, and for it they mean:

| Key | Certificate claim | Checked |
|---|---|---|
| `issuer` | `issuer` | equal; only GitHub Actions' issuer is supported |
| `repository` | `sourceRepositoryURI` | equals `https://github.com/<repository>`, ignoring case |
| `repository_id` | `sourceRepositoryIdentifier` | equal |
| `owner_id` | `sourceRepositoryOwnerIdentifier` | equal |
| `workflow` | `buildSignerURI` | the part before `@` is `https://github.com/<repository>/<workflow>` |
| `refs` | `sourceRepositoryRef`, and the ref after `@` in `buildSignerURI` | both match one of the globs |
| `runner` | `runnerEnvironment` | `github-hosted` or `self-hosted` |
| `predicate_type` | the statement's `predicateType` | equal |

- `repository_id` and `owner_id` are required alongside `repository`: if the account or
  repository is deleted or renamed, someone else can register the same name, but not the
  same numeric IDs. `gh api repos/OWNER/NAME --jq '.id, .owner.id'` prints them.
- `workflow` and `refs` are checked separately. Pinning only the ref would accept any
  workflow in the repository that can request an id-token.
- `refs` takes globs with the rules of Go's
  [`path.Match`](https://pkg.go.dev/path#Match): `*` does not cross a `/`, so
  `refs/tags/v*` matches `refs/tags/v1.2.0` but `refs/heads/*` does not match
  `refs/heads/release/1`.

**Optional: a minimum version.** Without one, an attacker holding the repository key can
serve an older, genuinely attested release with known vulnerabilities. A top-level
`min_version`, before `[match]`, refuses anything older by dpkg's version ordering:

```toml
min_version = "0.6.0-1"

[match]
…
```

To find the values for a package, run `apt-attest explain` on it with its bundle (see
below), or `gh attestation verify FILE --repo OWNER/NAME --format json`.

## Where the bundle comes from

A repository publishes each package's Sigstore bundle next to it, named exactly the
`.deb`'s file name plus `.sigstore.json`:

```
pool/main/pidvault_0.6.0-1_amd64.deb
pool/main/pidvault_0.6.0-1_amd64.deb.sigstore.json
```

The bundle comes from the same mirror as the package, so there is no GitHub API, no
token and no rate limit, and it works through proxies and local mirrors. Where it is
served from does not need to be trusted: verifying it is what makes it trusted.

The hook is given the local path of each `.deb`, not the URL it came from. To find the
URL, apt-attest hashes the file and looks for the record with that SHA256 in the
Packages indexes that `apt-get indextargets` lists, each with its source's base URL. The
bundle URL is that base URL, the record's `Filename:` and `.sigstore.json`. Matching on
the hash identifies the exact copy being installed, even when several sources carry the
same version with different contents, which `apt-cache show` and `apt-cache policy`
cannot tell apart. None of this takes apt's lock.

For a local install (`apt install ./pidvault_0.6.0-1_amd64.deb`), the bundle is looked
for next to the file. A covered package with no bundle there is refused.

The bundle is fetched over HTTP(S) or read from a `file:` source, through the proxy in
`Acquire::https::Proxy` or `Acquire::http::Proxy` if apt has one, else the environment's.

### Publishing bundles from a GitHub Actions release

[`actions/attest-build-provenance`](https://github.com/actions/attest-build-provenance)
writes the bundle it creates to the path in its `bundle-path` output. Copy it beside
each package, and copy the bundles into the repository's pool with the packages:

```yaml
- uses: actions/attest-build-provenance@4d101475d8b20a2381f78447822ac1eab6504dd8 # v4.2.2
  id: provenance
  with:
    subject-path: dist/*.deb
- name: Keep the provenance bundle beside each package
  env:
    BUNDLE: ${{ steps.provenance.outputs.bundle-path }}
  run: for deb in dist/*.deb; do cp "$BUNDLE" "$deb.sigstore.json"; done
```

One bundle can name several packages as subjects. Each package needs it under its own
name. The bundle must come from Sigstore's public-good instance, which is what
`attest-build-provenance` uses for public repositories.

## Behaviour

- **Fail closed.** A covered package with a missing, unreadable or failing bundle stops
  the install. The message names the package, the policy file and what did not match:

  ```
  apt-attest: refusing pidvault 0.6.0-1 (/var/cache/apt/archives/pidvault_0.6.0-1_amd64.deb): attestation does not match policy /etc/apt/attestations.d/pidvault.toml
    workflow: want https://github.com/torstei/pidvault/.github/workflows/release.yml, got https://github.com/torstei/pidvault/.github/workflows/ci.yml
  ```

  A broken policy file, or Packages indexes it cannot read, also stop the install.
- **Offline reinstall.** The claims of each attestation that verifies are cached in
  `/var/lib/apt-attest/verified/`, keyed by the package's SHA256, so reinstalling needs
  neither the bundle nor the network. Cached claims are checked against the current
  policies every time, so a policy change still applies.
- **Trusted root.** Sigstore's `trusted_root.json` is fetched through TUF from
  `tuf-repo-cdn.sigstore.dev` after each successful `apt update` and kept in
  `/var/lib/apt-attest/`. Until the first refresh, the copy built into apt-attest is
  used. A check never needs the network for it. `sudo apt-attest refresh` updates it by
  hand.
- **Removal.** If apt-attest is removed and its configuration kept, the hook does
  nothing, so apt keeps working.

## Commands

```
apt-attest check FILE.deb     check a package as the hook would; exit 1 if it would be refused
apt-attest explain FILE.deb   print the attestation's claims next to each policy's expectations
apt-attest refresh            fetch Sigstore's current trusted root
apt-attest hook               the APT hook; reads apt's hook protocol version 3 on stdin
```

`check` and `explain` look for the bundle beside the file, then on the sources that
carry it. `--bundle FILE` names one instead, `--policy-dir DIR` reads policies from
another directory, and `check --no-cache` verifies again even if the file has verified
before.

```
$ apt-attest explain --bundle pidvault_0.6.0-1_amd64.deb.sigstore.json pidvault_0.6.0-1_amd64.deb
…
policy /etc/apt/attestations.d/pidvault.toml
    field           want                                                               got
ok  issuer          https://token.actions.githubusercontent.com                        https://token.actions.githubusercontent.com
ok  repository      https://github.com/torstei/pidvault                                https://github.com/torstei/pidvault
ok  repository_id   1431302070                                                         1431302070
…
```

## Known limits

- **`dpkg -i` bypasses apt, and so bypasses the hook.** `apt install ./file.deb` is
  covered, and so is anything else that installs through libapt (unattended-upgrades,
  PackageKit).
- **Anyone who can run workflows in the attested repository can produce valid
  attestations.** The gain is that they cannot do so quietly: every attestation is in
  Rekor. The attestation says which commit built the package, not that the commit is
  safe.
- **It only protects systems that have installed it and have a policy for the
  repository.**
- Only attestations signed through Sigstore's public-good instance are accepted. GitHub
  signs attestations for private repositories with its own Sigstore instance, which
  apt-attest does not trust.
- `workflow` is checked against `buildSignerURI`, the workflow that signed. A release
  built by a reusable workflow in another repository is signed by that workflow, so a
  policy would have to name it.
- Bundles are fetched over `http`, `https` and `file` only. A source using another apt
  method (`mirror+`, `tor+`) fails the check for covered packages, unless the bundle is
  already cached. Credentials in `/etc/apt/auth.conf.d` are not used.

## Prior art

- [non7top/apt-cosign](https://github.com/non7top/apt-cosign) is an apt download method
  that checks indexes and packages against Sigstore bundles. Sources must be marked
  `[trusted=yes]`, so it replaces apt's GPG check rather than adding to it.
- apt-verify / apt-sigstore replaces `gpgv` and checks that distribution index files are
  recorded in Rekor. It does not check individual packages or provenance.
- [Debian bug #1061555](https://bugs.debian.org/1061555) asked for Sigstore support in
  apt itself; apt is building its own signature format instead.

## Development

```sh
go test ./...          # unit tests, including the real pidvault 0.6.0 bundle
test/e2e/run.sh        # signed local repositories and real installs, in a container
scripts/build-deb.sh 0.1.0 amd64 arm64
```

The built-in trusted root is `internal/trustroot/trusted_root.json`. To update it, run
`go run ./cmd/apt-attest refresh --state-dir DIR` and copy `DIR/trusted_root.json` over it.

## License

MIT or Apache-2.0, at your option.
