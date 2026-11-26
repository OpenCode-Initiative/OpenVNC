#!/usr/bin/env bash
# Captura Wayland de ponta a ponta: sway headless -> xdg-desktop-portal-wlr
# -> PipeWire -> openvnc-server -> vncviewer (Xvfb). portal-wlr nao tem
# RemoteDesktop, entao so a captura e testada aqui.
set -uo pipefail
BIN=${BIN:-target/release/openvnc-server}
export XDG_RUNTIME_DIR=$(mktemp -d); chmod 700 "$XDG_RUNTIME_DIR"
LOG=$(mktemp -d)
eval "$(dbus-launch --sh-syntax)"
export WLR_BACKENDS=headless WLR_RENDERER=pixman WLR_NO_HARDWARE_CURSORS=1 WLR_LIBINPUT_NO_DEVICES=1 XDG_CURRENT_DESKTOP=sway
mkdir -p ~/.config/sway ~/.config/xdg-desktop-portal-wlr
cat > ~/.config/sway/config <<'C'
output * bg #336699 solid_color
output HEADLESS-1 resolution 640x480
C
printf '[screencast]\nchooser_type=none\noutput_name=HEADLESS-1\n' > ~/.config/xdg-desktop-portal-wlr/config
sway >"$LOG/sway.log" 2>&1 &
for i in $(seq 50); do ls "$XDG_RUNTIME_DIR"/wayland-* >/dev/null 2>&1 && break; sleep 0.2; done
export WAYLAND_DISPLAY=$(basename "$(ls "$XDG_RUNTIME_DIR"/wayland-? | head -1)")
(foot -e sh -c "while :; do date; sleep 0.5; done" >/dev/null 2>&1 &)
pipewire >"$LOG/pw.log" 2>&1 & sleep 1
wireplumber >"$LOG/wp.log" 2>&1 & sleep 1
/usr/libexec/xdg-desktop-portal-wlr >"$LOG/xdpw.log" 2>&1 &
/usr/libexec/xdg-desktop-portal >"$LOG/xdp.log" 2>&1 & sleep 2
export OPENVNC_PASSWORD=interop
unset DISPLAY
RUST_LOG=info "$BIN" --listen 127.0.0.1:5904 --capture native --max-fps 15 >"$LOG/srv.log" 2>&1 &
SRV=$!
sleep 4
Xvfb :1 -screen 0 800x600x24 >/dev/null 2>&1 & sleep 1
echo interop | vncpasswd -f > "$LOG/passwd"
DISPLAY=:1 vncviewer -PasswordFile "$LOG/passwd" -Log '*:stderr:100' 127.0.0.1::5904 >"$LOG/viewer.log" 2>&1 &
sleep 6
DISPLAY=:1 import -window root "$LOG/shot.png"
kill $SRV 2>/dev/null || true
grep -E "stream PipeWire|captura|WARN|ERROR" "$LOG/srv.log" | head -10
grep -qiE "Using pixel format|connected to host" "$LOG/viewer.log" || { echo "PORTAL: sem captura"; grep -h "valid format" "$LOG/xdpw.log"; }
# fundo do sway (#336699) chegou ao viewer
convert "$LOG/shot.png" -format '%c' histogram:info:- | sort -rn | head -3
convert "$LOG/shot.png" -format "%c" histogram:info:- > "$LOG/h1.txt"; grep -qi "336699" "$LOG/h1.txt" && echo "PORTAL OK"

# Fase 2: caminho PipeWire de ponta a ponta sem portal (videotestsrc ->
# pipewiresink -> openvnc-server -> vncviewer). Necessario porque o
# xdg-desktop-portal-wlr 0.7 exige GPU (/dev/dri + gbm) para o screencopy.
gst-launch-1.0 -q videotestsrc pattern=solid-color foreground-color=0xff336699 \
  ! video/x-raw,format=BGRx,width=320,height=240,framerate=15/1 \
  ! pipewiresink stream-properties="props,media.class=Video/Source,node.name=openvnc-test" \
  >"$LOG/gst.log" 2>&1 &
sleep 2
NODE=$(pw-cli ls Node | awk '/^\tid /{id=$2} /node.name = "openvnc-test"/{print id+0; exit}')
echo "no de teste: $NODE"
OPENVNC_PIPEWIRE_NODE=$NODE RUST_LOG=info "$BIN" --listen 127.0.0.1:5905 --capture native --max-fps 15 >"$LOG/srv2.log" 2>&1 &
SRV=$!
sleep 3
DISPLAY=:1 vncviewer -PasswordFile "$LOG/passwd" -Log '*:stderr:100' 127.0.0.1::5905 >"$LOG/viewer2.log" 2>&1 &
sleep 5
DISPLAY=:1 import -window root "$LOG/shot2.png"
kill $SRV 2>/dev/null
grep -E "stream PipeWire|ERROR" "$LOG/srv2.log" | sed "s/\x1b\[[0-9;]*m//g"
grep -E "Using pixel format|Desktop size" "$LOG/viewer2.log" | head -2
convert "$LOG/shot2.png" -format '%c' histogram:info:- | sort -rn | head -2
convert "$LOG/shot2.png" -format "%c" histogram:info:- > "$LOG/h2.txt"; grep -qi "336699" "$LOG/h2.txt" || { echo "PIPEWIRE FALHOU"; cat "$LOG/srv2.log" "$LOG/gst.log" | tail -n 20; exit 1; }
echo PIPEWIRE OK
