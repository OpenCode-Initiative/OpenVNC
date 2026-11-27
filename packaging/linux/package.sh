#!/usr/bin/env bash
# Roda dentro do container: compila e gera .tar.gz e .deb em /out.
set -euo pipefail
: "${VER:?}"
mkdir -p /out
cd /work
cargo build --release --locked -p openvnc-desktop -p openvnc-server -p openvnc-config
R="$CARGO_TARGET_DIR/release"
BINS="openvnc-desktop openvnc-server openvnc-config"

# .tar.gz
T="openvnc-$VER-linux-x86_64"; rm -rf "/tmp/$T"; mkdir -p "/tmp/$T"
for b in $BINS; do install -m755 "$R/$b" "/tmp/$T/"; done
cp LICENSE* README* "/tmp/$T/" 2>/dev/null || true
tar -C /tmp -czf "/out/$T.tar.gz" "$T"

# .deb
P=/tmp/deb; rm -rf "$P"; mkdir -p "$P/DEBIAN" "$P/usr/bin" "$P/usr/share/applications" "$P/usr/share/icons/hicolor/256x256/apps"
for b in $BINS; do install -m755 "$R/$b" "$P/usr/bin/"; done
install -m644 assets/brand/openvnc-256.png "$P/usr/share/icons/hicolor/256x256/apps/openvnc.png"
desk() { cat > "$P/usr/share/applications/$1.desktop" <<D
[Desktop Entry]
Type=Application
Name=$2
Exec=$1
Icon=openvnc
Categories=Network;RemoteAccess;
D
}
desk openvnc-desktop "OpenVNC"
desk openvnc-config "OpenVNC Config"
cat > "$P/DEBIAN/control" <<C
Package: openvnc
Version: $VER
Section: net
Priority: optional
Architecture: amd64
Maintainer: OpenCode Initiative
Depends: libc6, libx11-6, libxcb1, libxkbcommon0, libgl1
Description: OpenVNC, acesso remoto compativel com VNC
 Cliente, servidor e configurador do OpenVNC.
C
dpkg-deb --root-owner-group --build "$P" "/out/openvnc_${VER}_amd64.deb"
