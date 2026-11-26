#!/usr/bin/env bash
# Sobe o servidor (test-pattern a 30 FPS e captura X11 de um Xvfb) e
# conecta o vncviewer do TigerVNC. Mede FPS (log do servidor) e CPU.
set -euo pipefail
BIN=${BIN:-target/release/openvnc-server}
export OPENVNC_PASSWORD=interop
LOG=$(mktemp -d)

Xvfb :1 -screen 0 800x600x24 >/dev/null 2>&1 &   # tela do viewer
Xvfb :2 -screen 0 640x480x24 >/dev/null 2>&1 &   # tela capturada
sleep 1
echo interop | vncpasswd -f > "$LOG/passwd"

check() { # nome porta args...
  local name=$1 port=$2; shift 2
  RUST_LOG=info "$BIN" --listen 127.0.0.1:$port "$@" >"$LOG/$name.log" 2>&1 &
  local srv=$!
  sleep 1
  DISPLAY=:1 vncviewer -PasswordFile "$LOG/passwd" -Log '*:stderr:100' \
    127.0.0.1::$port >"$LOG/$name.viewer.log" 2>&1 &
  local viewer=$!
  sleep 12
  local cpu
  cpu=$(ps -o %cpu= -p $srv | tr -d ' ')
  kill $viewer $srv 2>/dev/null || true
  wait $viewer $srv 2>/dev/null || true
  echo "== $name: CPU do servidor ${cpu}%"
  grep -E "estatisticas" "$LOG/$name.log" | tail -1
  grep -qiE "Using pixel format|connected to host" "$LOG/$name.viewer.log" \
    || { echo "viewer nao conectou"; cat "$LOG/$name.viewer.log"; exit 1; }
  grep -iE "encoding|pixel format" "$LOG/$name.viewer.log" | head -3
}

check pattern 5901 --capture test-pattern --max-fps 30
DISPLAY=:2 xclock -update 1 >/dev/null 2>&1 &
DISPLAY=:2 check x11 5902 --capture native --max-fps 30

# cliente OpenVNC contra o Xvnc (TigerVNC prefere Tight e manda Cursor/ExtendedDesktopSize)
CLI=${CLI:-target/release/openvnc}
Xvnc :3 -geometry 320x200 -depth 24 -rfbport 5903 -PasswordFile "$LOG/passwd"   -SecurityTypes VncAuth -localhost >"$LOG/xvnc.log" 2>&1 &
sleep 1
DISPLAY=:3 xsetroot -solid '#336699'
DISPLAY=:3 xclock -geometry 120x120+10+10 >/dev/null 2>&1 &
sleep 1
for shot in 1 2; do
  echo interop | NO_COLOR=1 RUST_LOG=openvnc_rfb=trace "$CLI" screenshot --password-stdin     -o "$LOG/xvnc$shot.png" 127.0.0.1::5903 2>"$LOG/cli$shot.log"
  [ $shot = 1 ] && DISPLAY=:3 xrandr -s 640x480 >/dev/null 2>&1 || true
done
echo "== cliente vs Xvnc: encodings recebidos"
sed "s/[[0-9;]*m//g" "$LOG"/cli*.log | grep -ohE "enc=-?[0-9]+" | sort | uniq -c
identify "$LOG/xvnc1.png" "$LOG/xvnc2.png"
# cor de fundo veio certa
convert "$LOG/xvnc1.png" -crop 1x1+300+190 txt:- | grep -qi "336699"   || { echo "fundo errado"; exit 1; }
echo OK
