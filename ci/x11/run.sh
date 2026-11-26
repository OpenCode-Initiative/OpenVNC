#!/usr/bin/env bash
# Captura X11 contra Xvfb: compara MIT-SHM com GetImage e mede o tempo por
# quadro em 1920x1080. Roda dentro da imagem de ci/interop.
set -euo pipefail
Xvfb :9 -screen 0 1920x1080x24 >/dev/null 2>&1 &
XVFB=$!
trap 'kill $XVFB' EXIT
for _ in $(seq 50); do [ -S /tmp/.X11-unix/X9 ] && break; sleep 0.2; done
export DISPLAY=:9
export OPENVNC_X11_SHM=1
# conteudo nao uniforme na raiz
xsetroot -bitmap /usr/include/X11/bitmaps/gray3 -fg '#336699' -bg '#cc8844' 2>/dev/null \
  || xsetroot -solid '#336699'
(xclock -geometry 400x400+100+100 >/dev/null 2>&1 &)
sleep 1
cargo test --release -p openvnc-platform x11::tests:: -- --ignored --nocapture --test-threads=1
