#!/bin/bash
# Runs inside a disposable Ubuntu container as root: builds two signed apt repositories,
# installs apt-attest, and checks what apt will and will not install.
# Usage: inside.sh APT_ATTEST_DEB PIDVAULT_DEB PIDVAULT_BUNDLE
set -euo pipefail

attest_deb=$1
pidvault_deb=$2
pidvault_bundle=$3
pv=$(basename "$pidvault_deb")

export DEBIAN_FRONTEND=noninteractive
apt_q=(-q -o Acquire::Retries=3 -o Dpkg::Use-Pty=0)

step() { printf '\n=== %s\n' "$*"; }
fail() { echo "FAIL: $*" >&2; exit 1; }

# must install: run apt, require success
installs() {
    local log=/tmp/apt.log
    if ! apt-get "${apt_q[@]}" install -y "$@" >"$log" 2>&1; then
        cat "$log"
        fail "apt-get install $* was refused"
    fi
    grep apt-attest "$log" || true
}

# must be refused, with each later argument in apt's output; $1 is apt-get install's
# arguments, split on spaces
refused() {
    local -a what
    read -r -a what <<<"$1"
    shift
    local log=/tmp/apt.log
    if apt-get "${apt_q[@]}" install -y "${what[@]}" >"$log" 2>&1; then
        cat "$log"
        fail "apt-get install ${what[*]} succeeded"
    fi
    for want in "$@"; do
        grep -qF -- "$want" "$log" || { cat "$log"; fail "refusal of ${what[*]} does not mention: $want"; }
    done
    grep apt-attest "$log"
}

not_installed() {
    if dpkg-query -W -f '${db:Status-Status}' "$1" 2>/dev/null | grep -q '^installed$'; then
        fail "$1 is installed"
    fi
}

step "tools"
rm -f /etc/apt/apt.conf.d/docker-clean
apt-get "${apt_q[@]}" update >/dev/null
apt-get "${apt_q[@]}" install -y --no-install-recommends gnupg apt-utils python3 systemd >/dev/null

step "apt-attest itself installs from a local file, with its own policy"
installs "$attest_deb"
apt-attest version
dpkg-query --showformat '${Conffiles}\n' -W apt-attest | grep -F /etc/apt/attestations.d/apt-attest.toml

step "a build of apt-attest that its release workflow did not make is refused"
refused "--reinstall $attest_deb" "refusing apt-attest 0.0.0~e2e-1" "/etc/apt/attestations.d/apt-attest.toml"

step "two signed repositories"
export GNUPGHOME=/tmp/gnupg
mkdir -m 700 "$GNUPGHOME"
gpg --batch --quiet --passphrase '' --quick-generate-key 'e2e repo <e2e@example.invalid>' ed25519 sign never
gpg --armor --export > /etc/apt/keyrings/e2e.asc

dummy() {
    local name=$1 dir
    dir=$(mktemp -d)
    mkdir -p "$dir/DEBIAN" "$dir/usr/share/$name"
    echo "$name" > "$dir/usr/share/$name/marker"
    printf 'Package: %s\nVersion: 1.0\nArchitecture: all\nMaintainer: e2e <e2e@example.invalid>\nDescription: e2e dummy\n' \
        "$name" > "$dir/DEBIAN/control"
    dpkg-deb --root-owner-group --build "$dir" "/tmp/${name}_1.0_all.deb" >/dev/null
}
dummy pidvault-helper
dummy unrelated-tool

publish() {
    local dir=$1
    (
        cd "$dir"
        mkdir -p dists/stable/main/binary-amd64
        apt-ftparchive packages pool > dists/stable/main/binary-amd64/Packages
        apt-ftparchive -o APT::FTPArchive::Release::Suite=stable -o APT::FTPArchive::Release::Codename=stable \
            -o APT::FTPArchive::Release::Architectures=amd64 -o APT::FTPArchive::Release::Components=main \
            release dists/stable > dists/stable/Release
        gpg --batch --yes --clearsign --output dists/stable/InRelease dists/stable/Release
    )
}
update() { apt-get "${apt_q[@]}" update >/dev/null; }

mkdir -p /srv/attested/pool/main /srv/other/pool/main
cp "$pidvault_deb" "$pidvault_bundle" /tmp/pidvault-helper_1.0_all.deb /srv/attested/pool/main/
cp /tmp/unrelated-tool_1.0_all.deb /srv/other/pool/main/
(cd /srv/attested && exec python3 -m http.server -b 127.0.0.1 8001 >/dev/null 2>&1) &
attested_server=$!
(cd /srv/other && exec python3 -m http.server -b 127.0.0.1 8002 >/dev/null 2>&1) &
for port in 8001 8002; do
    for _ in $(seq 50); do python3 -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:$port/')" 2>/dev/null && break; sleep 0.1; done
done
cat > /etc/apt/sources.list.d/e2e.list <<EOF
deb [signed-by=/etc/apt/keyrings/e2e.asc] http://127.0.0.1:8001 stable main
deb [signed-by=/etc/apt/keyrings/e2e.asc] http://127.0.0.1:8002 stable main
EOF
publish /srv/attested
publish /srv/other
update

step "the pidvault policy, matching by name and by origin"
sed 's|https://torstei.github.io/pidvault|http://127.0.0.1:8001|' \
    "$(dirname "$0")/pidvault.toml" > /etc/apt/attestations.d/pidvault.toml
cat /etc/apt/attestations.d/pidvault.toml

step "a package no policy covers installs untouched"
installs unrelated-tool

step "an unattested package under a new name, from the pinned origin, is refused"
refused pidvault-helper "refusing pidvault-helper 1.0" "/etc/apt/attestations.d/pidvault.toml" "pidvault-helper_1.0_all.deb.sigstore.json: not found"
not_installed pidvault-helper

# Rewrites one package's stanza in the attested repository's index the way someone
# holding the repository key could, then re-signs it.
tamper() {
    local name=$1 how=$2
    dummy "$name"
    cp "/tmp/${name}_1.0_all.deb" /srv/attested/pool/main/
    publish /srv/attested
    python3 - /srv/attested/dists/stable/main/binary-amd64/Packages "$name" "$how" <<'PY'
import sys
path, name, how = sys.argv[1:]
stanzas = open(path).read().strip().split("\n\n")
for i, s in enumerate(stanzas):
    if f"Package: {name}\n" in s:
        if how == "lowercase-fields":
            s = "\n".join(l if l.startswith(" ") else l.split(":", 1)[0].lower() + ":" + l.split(":", 1)[1] for l in s.split("\n"))
        elif how == "uppercase-name":
            s = s.replace(f"Package: {name}", f"Package: {name.upper()}")
        stanzas[i] = s
open(path, "w").write("\n\n".join(stanzas) + "\n")
PY
    (
        cd /srv/attested
        apt-ftparchive -o APT::FTPArchive::Release::Suite=stable -o APT::FTPArchive::Release::Codename=stable \
            -o APT::FTPArchive::Release::Architectures=amd64 -o APT::FTPArchive::Release::Components=main \
            release dists/stable > dists/stable/Release
        gpg --batch --yes --clearsign --output dists/stable/InRelease dists/stable/Release
    )
    update
}

step "an unattested package whose index stanza has lowercase field names is still refused"
tamper evil-lowercase lowercase-fields
refused evil-lowercase "refusing evil-lowercase 1.0"
not_installed evil-lowercase

step "an unattested package whose index stanza has an uppercase name is still refused"
tamper evil-uppercase uppercase-name
refused evil-uppercase "refusing evil-uppercase 1.0"
not_installed evil-uppercase
publish /srv/attested
update

step "apt-attest policies finds the policy's origin among apt's sources"
apt-attest policies > /tmp/policies.txt || true
cat /tmp/policies.txt
grep -F "http://127.0.0.1:8001: matches http://127.0.0.1:8001/" /tmp/policies.txt
mkdir -p /tmp/p
sed 's|http://127.0.0.1:8001|https://127.0.0.1:8009|' /etc/apt/attestations.d/pidvault.toml > /tmp/p/x.toml
apt-attest policies --policy-dir /tmp/p && fail "an origin no source matches went unreported"

step "pidvault with its bundle missing from the repository is checked against its GitHub release"
mv "/srv/attested/pool/main/$pv.sigstore.json" /tmp/held-bundle
installs pidvault
grep -F "https://github.com/torstei/pidvault/releases/download/v0.6.0/$pv.sigstore.json" /tmp/apt.log
apt-get "${apt_q[@]}" remove -y pidvault >/dev/null
rm -rf /var/lib/apt-attest/verified /var/cache/apt/archives/pidvault_*.deb
mv /tmp/held-bundle "/srv/attested/pool/main/$pv.sigstore.json"

step "a different pidvault file under the same name and version, with the real bundle, is refused"
rm -rf /tmp/repack && dpkg-deb -R "$pidvault_deb" /tmp/repack
echo tampered >> /tmp/repack/usr/share/doc/pidvault/copyright
dpkg-deb --root-owner-group --build /tmp/repack "/srv/attested/pool/main/$pv" >/dev/null
publish /srv/attested
update
rm -f /var/cache/apt/archives/pidvault_*.deb
refused pidvault "refusing pidvault 0.6.0-1" "bundle is for $pv sha256:b9a2a2189cb75b23262dca925dff67fe0d61ae8b2f220c2d039a10d992c8ae80, not this file"
not_installed pidvault

step "the attested pidvault installs"
cp "$pidvault_deb" "/srv/attested/pool/main/$pv"
publish /srv/attested
update
rm -f /var/cache/apt/archives/pidvault_*.deb
installs pidvault
dpkg-query -W pidvault

step "a reinstall works with the repository offline, from the cache of verified attestations"
kill "$attested_server"
wait "$attested_server" 2>/dev/null || true
apt-get "${apt_q[@]}" install -y --reinstall pidvault >/tmp/apt.log 2>&1 || { cat /tmp/apt.log; fail "offline reinstall refused"; }
grep -F "apt-attest: pidvault 0.6.0-1 attested by" /tmp/apt.log | grep -F cache

step "a policy change applies to cached attestations"
sed -i 's|release.yml|other.yml|' /etc/apt/attestations.d/pidvault.toml
refused "--reinstall pidvault" "workflow: want https://github.com/torstei/pidvault/.github/workflows/other.yml"
sed -i 's|other.yml|release.yml|' /etc/apt/attestations.d/pidvault.toml

step "a lone downloaded pidvault is checked against its GitHub release"
apt-get "${apt_q[@]}" remove -y pidvault >/dev/null
sed -i '/8001/d' /etc/apt/sources.list.d/e2e.list
update
apt-get clean
rm -rf /var/lib/apt-attest/verified
mkdir -p /tmp/local
cp "$pidvault_deb" "/tmp/local/download (1).deb"
installs "/tmp/local/download (1).deb"
grep -F "https://github.com/torstei/pidvault/releases/download/v0.6.0/$pv.sigstore.json" /tmp/apt.log
apt-get "${apt_q[@]}" remove -y pidvault >/dev/null

step "a local install uses the bundle beside the file first"
rm -rf /var/lib/apt-attest/verified
cp "$pidvault_deb" "$pidvault_bundle" /tmp/local/
installs "/tmp/local/$pv"
grep -F "(/etc/apt/attestations.d/pidvault.toml, /tmp/local/$pv.sigstore.json)" /tmp/apt.log
apt-get "${apt_q[@]}" remove -y pidvault >/dev/null

step "a tampered local pidvault is refused, and told how to go on"
mkdir -p /tmp/tampered
dpkg-deb --root-owner-group --build /tmp/repack "/tmp/tampered/$pv" >/dev/null
refused "/tmp/tampered/$pv" "refusing pidvault 0.6.0-1" "api.github.com/repos/torstei/pidvault/attestations/sha256:" "sudo dpkg -i /tmp/tampered/$pv"
not_installed pidvault

step "a broken policy stops every install"
echo 'refz = ["x"]' >> /etc/apt/attestations.d/pidvault.toml
refused "--reinstall unrelated-tool" "broken policy" "unknown keys: identity.refz"
rm /etc/apt/attestations.d/pidvault.toml

step "apt keeps working after apt-attest is removed with its conffile kept"
apt-get "${apt_q[@]}" remove -y apt-attest >/dev/null
test -e /etc/apt/apt.conf.d/20apt-attest
apt-get "${apt_q[@]}" install -y --reinstall unrelated-tool >/dev/null

echo
echo "e2e: all checks passed"
