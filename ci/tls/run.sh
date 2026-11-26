#!/usr/bin/env bash
# VeNCrypt/TLS de ponta a ponta (sem tela real: Xvnc vazio e test-pattern).
#  1. openvnc (cliente) x Xvnc do TigerVNC com -SecurityTypes X509Vnc
#  2. openvnc (cliente) x openvnc-server --require-tls --pairing
# Uso: BIN=.../openvnc-server CLI=.../openvnc bash ci/tls/run.sh
set -euo pipefail
BIN=${BIN:-target/release/openvnc-server}
CLI=${CLI:-target/release/openvnc}
S=$(mktemp -d)
trap 'kill $(jobs -p) 2>/dev/null || true; rm -rf "$S"' EXIT
fail() { echo "FALHOU: $*"; exit 1; }

FP=$("$BIN" --state-dir "$S" fingerprint)
echo "impressao digital: $FP"

# 1. TigerVNC Xvnc com o mesmo certificado
echo segredo1 | vncpasswd -f > "$S/pw"
Xvnc :7 -geometry 320x200 -SecurityTypes X509Vnc -X509Cert "$S/server.crt" \
  -X509Key "$S/server.key" -PasswordFile "$S/pw" >"$S/xvnc.log" 2>&1 &
sleep 2
echo segredo1 | "$CLI" info 127.0.0.1:7 --pin "$FP" --password-stdin | tee "$S/o"
grep -q "TLS 1.3" "$S/o" || fail "Xvnc X509Vnc"
echo segredo1 | "$CLI" info 127.0.0.1:7 --password-stdin && fail "aceitou sem TLS"
echo outra | "$CLI" info 127.0.0.1:7 --pin "$FP" --password-stdin && fail "senha errada aceita"
echo segredo1 | "$CLI" info 127.0.0.1:7 --pin "00${FP:2}" --password-stdin && fail "pin errado aceito"

# 2. servidor de referencia com pareamento
OUT=$("$BIN" --state-dir "$S" pair add ci)
ID=$(awk '/^dispositivo/{print $2}' <<<"$OUT")
TOK=$(awk '/^token/{print $2}' <<<"$OUT")
"$BIN" --state-dir "$S" --listen 127.0.0.1:5977 --require-tls --pairing >"$S/srv.log" 2>&1 &
sleep 1
echo "$TOK" | "$CLI" info 127.0.0.1::5977 --pin "$FP" --user "$ID" --password-stdin | tee "$S/o"
grep -q "X509Plain" "$S/o" || fail "dispositivo pareado"
echo "$TOK" | "$CLI" screenshot 127.0.0.1::5977 --pin "$FP" --user "$ID" --password-stdin -o "$S/s.png"
"$BIN" --state-dir "$S" pair revoke "$ID"
echo "$TOK" | "$CLI" info 127.0.0.1::5977 --pin "$FP" --user "$ID" --password-stdin && fail "revogado aceito"
grep -q '"reason":"revoked"' "$S/audit.log" || fail "auditoria sem revogacao"
echo "OK: VeNCrypt com Xvnc e com o servidor de referencia"
