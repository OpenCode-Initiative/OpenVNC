#!/usr/bin/env bash
# APK Android do cliente. Uso: build.sh VERSAO DIST
set -euo pipefail
VER="$1"; DIST="$(mkdir -p "$2" && cd "$2" && pwd)"
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
if [ ! -f "$ROOT/clients/android/Cargo.toml" ]; then
  echo "AVISO android: cliente Android (clients/android) ainda nao existe; pulando."
  exit 0
fi
command -v cargo-apk >/dev/null || { echo "instale: cargo install cargo-apk"; exit 1; }
[ -n "${ANDROID_NDK_ROOT:-}" ] || { echo "defina ANDROID_NDK_ROOT (instale o NDK pelo SDK Manager)"; exit 1; }
# Assinatura: para publicar, defina CARGO_APK_RELEASE_KEYSTORE e
# CARGO_APK_RELEASE_KEYSTORE_PASSWORD com a chave da empresa. Sem isso o APK
# sai assinado com a chave de depuracao padrao do Android (so para testes).
if [ -z "${CARGO_APK_RELEASE_KEYSTORE:-}" ]; then
  KS="$HOME/.android/debug.keystore"
  if [ ! -f "$KS" ]; then
    mkdir -p "$HOME/.android"
    keytool -genkeypair -keystore "$KS" -storepass android -keypass android       -alias androiddebugkey -keyalg RSA -keysize 2048 -validity 10000       -dname "CN=Android Debug,O=Android,C=US" >/dev/null
  fi
  echo "AVISO android: assinando com a chave de depuracao ($KS)."
  export CARGO_APK_RELEASE_KEYSTORE="$KS" CARGO_APK_RELEASE_KEYSTORE_PASSWORD=android
fi
cd "$ROOT/clients/android"
cargo apk build --release
mkdir -p "$DIST"
cp "${CARGO_TARGET_DIR:-$ROOT/target}"/release/apk/OpenVNC.apk "$DIST/OpenVNC-$VER-android.apk"
