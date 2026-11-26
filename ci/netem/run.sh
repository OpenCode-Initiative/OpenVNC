#!/usr/bin/env bash
# TCP, TCP+TLS e QUIC sob perda e latencia (netem no loopback).
# Exige Linux com `tc` e CAP_NET_ADMIN (container com --cap-add NET_ADMIN).
#
# MIB e PINGS podem ser ajustados por variavel de ambiente.
set -euo pipefail
MIB=${MIB:-32}
PINGS=${PINGS:-200}
cargo build --release -p openvnc-transport --example bench_transport
BIN=${CARGO_TARGET_DIR:-target}/release/examples/bench_transport
trap 'tc qdisc del dev lo root 2>/dev/null || true' EXIT
for cond in "delay 0ms" "delay 25ms" "delay 25ms loss 1%" "delay 50ms loss 3%"; do
  tc qdisc del dev lo root 2>/dev/null || true
  # shellcheck disable=SC2086
  tc qdisc add dev lo root netem $cond
  echo "=== netem: $cond (por sentido; RTT = 2x) ==="
  "$BIN" "$MIB" "$PINGS"
done
