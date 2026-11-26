#!/usr/bin/env bash
# Gera o .dmg do macOS em uma maquina Mac remota via SSH, a partir do working
# tree local (inclusive mudancas nao commitadas), e traz o .dmg de volta.
#
# Uso: packaging/macos/build-remote.sh 0.4.3 [--release]
#   --release  anexa o .dmg na release vVERSAO do GitHub (gh release upload)
#
# Configuracao (variaveis de ambiente ou packaging/macos/remote.env, nao versionado):
#   MAC_HOST    usuario@ip da VM
#   MAC_KEY     chave SSH (padrao ~/.ssh/openvnc_mac)
#   MAC_SRC     diretorio do codigo no Mac
#   MAC_SCRIPT  script de build no Mac (recebe a versao)
#   MAC_OUT     diretorio onde o Mac grava o .dmg
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
[ -f "$ROOT/packaging/macos/remote.env" ] && . "$ROOT/packaging/macos/remote.env"

VER="${1:?informe a versao, ex.: 0.4.3}"
RELEASE="${2:-}"
: "${MAC_HOST:?defina MAC_HOST}" "${MAC_SRC:?defina MAC_SRC}" "${MAC_SCRIPT:?defina MAC_SCRIPT}" "${MAC_OUT:?defina MAC_OUT}"
MAC_KEY="${MAC_KEY:-$HOME/.ssh/openvnc_mac}"
SSH=(ssh -i "$MAC_KEY" -o BatchMode=yes -o StrictHostKeyChecking=accept-new "$MAC_HOST")
DMG="OpenVNC-$VER-macos-x86_64.dmg"
DEST="${DEST:-$HOME/Downloads}"

echo "==> enviando codigo para $MAC_HOST:$MAC_SRC"
cd "$ROOT"
# arquivos versionados + nao versionados nao ignorados (respeita .gitignore)
git ls-files -z --cached --others --exclude-standard \
  | tar --null -T - -czf - \
  | "${SSH[@]}" "mkdir -p '$MAC_SRC' && cd '$MAC_SRC' && tar -xzf -"

echo "==> compilando e empacotando $DMG no Mac"
"${SSH[@]}" "bash \"$MAC_SCRIPT\" \"$VER\""

echo "==> baixando $DMG para $DEST"
scp -i "$MAC_KEY" -o BatchMode=yes "$MAC_HOST:$MAC_OUT/$DMG" "$DEST/$DMG"
ls -la "$DEST/$DMG"

if [ "$RELEASE" = "--release" ]; then
  echo "==> anexando na release v$VER"
  gh release upload "v$VER" "$DEST/$DMG" --clobber
fi
echo "ok"
