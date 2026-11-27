#!/usr/bin/env bash
# Pacotes Linux x86_64 (.tar.gz e .deb), compilados em container (podman ou docker).
# Uso: build.sh VERSAO DIST
set -euo pipefail
VER="$1"; mkdir -p "$2"; DIST="$(cd "$2" && pwd)"
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
ENGINE="${ENGINE:-$(command -v podman || command -v docker || true)}"
[ -n "$ENGINE" ] || { echo "podman ou docker necessario para o build Linux"; exit 1; }
IMG=openvnc-linux-build

"$ENGINE" build -q -t "$IMG" -f "$ROOT/packaging/linux/Containerfile" "$ROOT/packaging/linux"
# o target fica num volume nomeado: builds incrementais e nada de target/ Linux no Windows
"$ENGINE" volume create openvnc-linux-target >/dev/null 2>&1 || true
"$ENGINE" volume create openvnc-cargo-registry >/dev/null 2>&1 || true

# o codigo vai por stdin e os pacotes voltam por stdout (funciona mesmo quando a
# VM do podman/docker nao enxerga o disco do projeto)
INNER='mkdir -p /work && tar -xf - -C /work && bash /work/packaging/linux/package.sh >&2 && tar -C /out -cf - .'
cd "$ROOT"
git ls-files -z --cached --others --exclude-standard \
  | tar --null -T - -cf - \
  | MSYS_NO_PATHCONV=1 "$ENGINE" run --rm -i \
      -v openvnc-linux-target:/target \
      -v openvnc-cargo-registry:/usr/local/cargo/registry \
      -e CARGO_TARGET_DIR=/target -e VER="$VER" \
      "$IMG" bash -c "$INNER" \
  | tar -xf - -C "$DIST"
ls -la "$DIST"/openvnc*"$VER"*
