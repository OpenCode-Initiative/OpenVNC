#!/usr/bin/env bash
# IPA iOS do cliente, gerado no Mac remoto (exige Xcode completo e conta Apple Developer).
# Uso: build.sh VERSAO DIST
set -euo pipefail
VER="$1"; DIST="$2"
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
if [ ! -d "$ROOT/clients/ios" ]; then
  echo "AVISO ios: cliente iOS (clients/ios) ainda nao existe; pulando."
  exit 0
fi
echo "ios: build remoto ainda nao implementado (requer Xcode completo no Mac e certificado de distribuicao)."
exit 1
