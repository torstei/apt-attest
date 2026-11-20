#!/bin/bash
# Builds a signed apt repository from the .deb files in DEBS into OUT: suite and codename
# "stable", component "main", amd64 and arm64. Signs with KEY, which must be in gpg's
# keyring. A package's provenance bundle, DEB.sigstore.json in DEBS, is published beside it.
# Usage: scripts/build-apt-repo.sh DEBS OUT KEY
set -euo pipefail

debs=$(realpath "$1")
out=$2
key=$3
archs=(amd64 arm64)

rm -rf "$out"
mkdir -p "$out/pool/main"
cp "$debs"/*.deb "$out/pool/main/"
find "$debs" -maxdepth 1 -name '*.deb.sigstore.json' -exec cp -t "$out/pool/main/" {} +
cd "$out"

for arch in "${archs[@]}"; do
    mkdir -p "dists/stable/main/binary-$arch"
    apt-ftparchive --arch "$arch" packages pool > "dists/stable/main/binary-$arch/Packages"
    gzip -9 -k -n "dists/stable/main/binary-$arch/Packages"
done
apt-ftparchive \
    -o APT::FTPArchive::Release::Origin=apt-attest \
    -o APT::FTPArchive::Release::Label=apt-attest \
    -o APT::FTPArchive::Release::Suite=stable \
    -o APT::FTPArchive::Release::Codename=stable \
    -o APT::FTPArchive::Release::Architectures="${archs[*]}" \
    -o APT::FTPArchive::Release::Components=main \
    release dists/stable > dists/stable/Release

gpg --batch --yes --local-user "$key" --clearsign --output dists/stable/InRelease dists/stable/Release
gpg --batch --yes --local-user "$key" --armor --detach-sign --output dists/stable/Release.gpg dists/stable/Release
gpg --armor --export "$key" > apt-attest.asc
fingerprint=$(gpg --with-colons --fingerprint "$key" | awk -F: '$1 == "fpr" { print $10; exit }')

cat > index.html <<HTML
<!doctype html>
<meta charset="utf-8">
<title>apt-attest apt repository</title>
<h1>apt-attest apt repository</h1>
<p>amd64 and arm64. See <a href="https://github.com/torstei/apt-attest">the project</a>.</p>
<pre>
sudo curl -fsSLo /etc/apt/keyrings/apt-attest.asc https://torstei.github.io/apt-attest/apt-attest.asc
echo "deb [signed-by=/etc/apt/keyrings/apt-attest.asc] https://torstei.github.io/apt-attest stable main" \\
  | sudo tee /etc/apt/sources.list.d/apt-attest.list
sudo apt update &amp;&amp; sudo apt install apt-attest
sudo cp /usr/share/doc/apt-attest/examples/apt-attest.toml /etc/apt/attestations.d/
</pre>
<p>The last line makes apt-attest check its own upgrades: only packages its release
workflow built and attested are installed from this repository.</p>
<p>Signing key fingerprint: <code>$fingerprint</code></p>
HTML
