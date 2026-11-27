#!/bin/bash
# Uso: build-dmg.sh VERSAO   (codigo em ~/openvnc-build/src, saida em ~/openvnc-build/out)
set -euo pipefail
V="${1:?uso: build-dmg.sh VERSAO}"
[ -f "$HOME/.cargo/env" ] && source "$HOME/.cargo/env"
export PATH="$HOME/.cargo/bin:/usr/bin:/bin:/usr/sbin:/sbin:$PATH"
SRC="$HOME/openvnc-build/src"; OUT="$HOME/openvnc-build/out"; ST="$HOME/openvnc-build/stage"
cd "$SRC"
cargo build --release -p openvnc-desktop -p openvnc-server -p openvnc-config
R="$SRC/target/release"; rm -rf "$ST"; mkdir -p "$ST" "$OUT"
# icone .icns a partir do PNG da marca
IS="$ST/openvnc.iconset"; mkdir -p "$IS"
for s in 16 32 128 256 512; do
  sips -z $s $s assets/brand/openvnc-512.png --out "$IS/icon_${s}x${s}.png" >/dev/null
  d=$((s*2)); [ $d -le 512 ] && sips -z $d $d assets/brand/openvnc-512.png --out "$IS/icon_${s}x${s}@2x.png" >/dev/null
done
cp assets/brand/openvnc-512.png "$IS/icon_256x256@2x.png"
iconutil -c icns "$IS" -o "$ST/openvnc.icns"; rm -rf "$IS"
mk() { # nome_app binario id
  local A="$ST/$1.app"; mkdir -p "$A/Contents/MacOS" "$A/Contents/Resources"; cp "$R/$2" "$A/Contents/MacOS/"
  cp "$ST/openvnc.icns" "$A/Contents/Resources/openvnc.icns"
  cat > "$A/Contents/Info.plist" <<P
<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd"><plist version="1.0"><dict>
<key>CFBundleExecutable</key><string>$2</string><key>CFBundleIdentifier</key><string>org.opencode-initiative.$3</string>
<key>CFBundleIconFile</key><string>openvnc</string><key>CFBundleName</key><string>$1</string><key>CFBundlePackageType</key><string>APPL</string>
<key>CFBundleShortVersionString</key><string>$V</string><key>CFBundleVersion</key><string>$V</string>
<key>LSMinimumSystemVersion</key><string>11.0</string><key>NSHighResolutionCapable</key><true/>
<key>NSScreenCaptureUsageDescription</key><string>O OpenVNC Server precisa capturar a tela para compartilha-la.</string>
<key>NSAppleEventsUsageDescription</key><string>O OpenVNC precisa controlar teclado e mouse remotamente.</string>
</dict></plist>
P
  codesign --force --deep -s - "$A"
}
mk "OpenVNC" openvnc-desktop desktop
mk "OpenVNC Server" openvnc-server server
mk "OpenVNC Config" openvnc-config config
rm -f "$ST/openvnc.icns"
ln -s /Applications "$ST/Applications"
D="$OUT/OpenVNC-$V-macos-x86_64.dmg"; rm -f "$D"
hdiutil create -volname "OpenVNC $V" -srcfolder "$ST" -ov -format UDZO "$D" >/dev/null
hdiutil verify "$D" >/dev/null
echo "$D"
