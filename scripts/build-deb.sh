#!/bin/bash
# Builds dist/apt-attest_VERSION-1_ARCH.deb for each ARCH (default amd64). The build is
# reproducible: SOURCE_DATE_EPOCH (default: the last commit's time) sets every timestamp.
# Usage: scripts/build-deb.sh VERSION [ARCH...]
set -euo pipefail
umask 022

version=$1
shift
archs=("${@:-amd64}")
cd "$(dirname "$0")/.."
export SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH:-$(git log -1 --format=%ct)}
mkdir -p dist

for arch in "${archs[@]}"; do
    root=$(mktemp -d)
    chmod 755 "$root"
    trap 'rm -rf "$root"' EXIT

    install -d "$root/DEBIAN" "$root/usr/bin" "$root/etc/apt/apt.conf.d" "$root/etc/apt/attestations.d" \
        "$root/var/lib/apt-attest" "$root/usr/share/doc/apt-attest/examples"
    CGO_ENABLED=0 GOOS=linux GOARCH=$arch go build -trimpath -buildvcs=false \
        -ldflags "-s -w -X main.version=$version" -o "$root/usr/bin/apt-attest" ./cmd/apt-attest
    install -m 644 packaging/20apt-attest "$root/etc/apt/apt.conf.d/20apt-attest"
    install -m 644 README.md packaging/copyright "$root/usr/share/doc/apt-attest/"
    install -m 644 examples/*.toml "$root/usr/share/doc/apt-attest/examples/"
    install -m 755 packaging/postrm "$root/DEBIAN/postrm"
    echo /etc/apt/apt.conf.d/20apt-attest > "$root/DEBIAN/conffiles"
    cat > "$root/DEBIAN/control" <<CONTROL
Package: apt-attest
Version: $version-1
Architecture: $arch
Maintainer: Torstein Tauno Svendsen <torstei@gmail.com>
Depends: apt (>= 1.1), dpkg
Section: admin
Priority: optional
Homepage: https://github.com/torstei/apt-attest
Installed-Size: $(du -sk --exclude=DEBIAN "$root" | cut -f1)
Description: check build provenance before apt installs a package
 An APT hook that, before dpkg unpacks a package a policy covers, verifies the
 package's Sigstore attestation and checks that it was made by the build the
 policy expects: repository, workflow, ref and runner. A package that fails
 the check is not installed. Packages no policy covers are left alone.
CONTROL

    chmod -R go-w "$root"
    find "$root" -exec touch --no-dereference --date="@$SOURCE_DATE_EPOCH" {} +
    dpkg-deb --root-owner-group -Zxz --build "$root" "dist/apt-attest_${version}-1_${arch}.deb" >/dev/null
    rm -rf "$root"
    trap - EXIT
    echo "dist/apt-attest_${version}-1_${arch}.deb"
done
