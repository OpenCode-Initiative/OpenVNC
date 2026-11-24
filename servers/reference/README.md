# openvnc-server (referência)

Servidor RFB 3.8 com VNC Auth, Raw/Hextile/ZRLE/CopyRect, dirty rects por tiles 64x64, detecção de rolagem e vários clientes compartilhando a captura.

```sh
OPENVNC_PASSWORD=segredo openvnc-server --listen 127.0.0.1:5900 --capture test-pattern
openvnc-server -c servidor.toml   # ver --help
```

Os padrões são seguros: escuta só em loopback e exige senha. Sem senha, só roda com `allow_no_auth = true` explícito. Capturas disponíveis: `test-pattern` e `x11` (Linux, `$DISPLAY`).
