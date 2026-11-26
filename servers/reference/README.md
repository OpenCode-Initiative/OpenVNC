# openvnc-server (referência)

Servidor RFB 3.8 com VNC Auth, Raw/Hextile/ZRLE/CopyRect, dirty rects por tiles 64x64, detecção de rolagem e vários clientes compartilhando a captura.

```sh
OPENVNC_PASSWORD=segredo openvnc-server --listen 127.0.0.1:5900 --capture test-pattern
openvnc-server -c servidor.toml   # ver --help
```

Os padrões são seguros: escuta só em loopback e exige senha. Sem senha, só roda com `allow_no_auth = true` explícito. Capturas disponíveis: `test-pattern` e `x11` (Linux, `$DISPLAY`).

## TLS, pareamento e auditoria (v0.3)

```sh
openvnc-server fingerprint                 # gera o certificado autoassinado e mostra o SHA-256
openvnc-server pair add notebook           # mostra id e token (uma vez so)
openvnc-server pair list
openvnc-server pair revoke dev-xxxxxxxxxxxx
openvnc-server --require-tls --pairing     # so VeNCrypt; dispositivos pareados
```

No cliente: `echo $TOKEN | openvnc info host --pin $SHA256 --user dev-... --password-stdin`.
`--tls` oferece VeNCrypt junto dos tipos em claro; `--require-tls` oferece só VeNCrypt. O estado (certificado, `devices`, `audit.log`) fica em `--state-dir` (padrão `OPENVNC_SERVER_DIR`, `%APPDATA%/openvnc-server` ou `~/.local/share/openvnc-server`).
