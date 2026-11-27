#!/usr/bin/env bash
# Instalador Windows (Inno Setup). Uso: build.sh VERSAO DIST
set -euo pipefail
VER="$1"; DIST="$(mkdir -p "$2" && cd "$2" && pwd)"
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"; cd "$ROOT"
ISCC="${ISCC:-$LOCALAPPDATA/Programs/Inno Setup 6/ISCC.exe}"
[ -x "$ISCC" ] || ISCC="/c/Program Files (x86)/Inno Setup 6/ISCC.exe"
[ -x "$ISCC" ] || { echo "Inno Setup 6 nao encontrado (defina ISCC)"; exit 1; }

cargo build --release --locked -p openvnc-config -p openvnc-server -p openvnc-desktop -p openvnc-cli
TGT="${CARGO_TARGET_DIR:-$ROOT/target}"
MSYS2_ARG_CONV_EXCL="*" MSYS_NO_PATHCONV=1 "$ISCC" -Q "/DAppVersion=$VER" "/DBinDir=$(cygpath -w "$TGT/release")" "/O$(cygpath -w "$DIST")" \
  packaging/windows/openvnc.iss
ls -la "$DIST/OpenVNC-Setup-$VER.exe"
