# OpenVNC

Acesso remoto open-source, moderno e comunitário — compatível com o ecossistema VNC (RFB 3.3/3.7/3.8, RFC 6143) e com um protocolo nativo seguro (TLS 1.3 / QUIC) em evolução.

> **Status:** Fase 1 (v0.1) — cliente RFB legado (CLI + desktop) implementado; interoperabilidade com servidores reais ainda em validação. Veja [PLANO.md](PLANO.md).

## Princípios
- Compatibilidade antes de inovação: implementar o RFB corretamente, sem inventar versões.
- Sem criptografia nem codecs próprios: rustls, quinn, H.264/AV1.
- Sem dependência de nuvem: conexão direta por IP.
- Protocolo independente de linguagem + C ABI para qualquer linguagem.

## Estrutura
| Caminho | Conteúdo |
|---|---|
| `core/crates/` | Bibliotecas Rust (implementação de referência) |
| `clients/cli`, `clients/desktop` | Cliente de linha de comando e gráfico (egui; OpenGL/glow por padrão, `OPENVNC_RENDERER=wgpu` opcional) |
| `fuzz/` | Alvos cargo-fuzz (fora do workspace) |
| `docs/` | Arquitetura, protocolos, segurança, compatibilidade |
| `PLANO.md` | Plano de implementação por fases |

## Compilando
```sh
cargo test --workspace
cargo run -p openvnc-desktop                      # cliente gráfico
cargo run -p openvnc-cli -- info host:1           # dados do servidor
cargo run -p openvnc-cli -- screenshot host:1 -o tela.png
```
Requer Rust estável (MSRV 1.80). Endereços: `host:N` = display (porta 5900+N), `host::porta` = porta explícita.
A senha vem de `OPENVNC_PASSWORD` ou `--password-stdin` (nunca por argumento).

## Segurança: use túnel SSH
VNC legado **não é criptografado** e o VNC Auth (DES) é fraco; os clientes avisam isso. Em redes não confiáveis:
```sh
ssh -L 5901:localhost:5901 usuario@servidor
openvnc screenshot localhost:1 -o tela.png
openvnc type localhost:1 --at 100,100 "texto"   # clica e digita (teste de entrada)
```

## Suportado na v0.1
RFB 3.3/3.7/3.8 · segurança None e VNC Auth · encodings Raw, CopyRect, Hextile, ZRLE · teclado/mouse/clipboard (Latin-1) · reconexão com backoff.
Fuzzing: `cd fuzz && cargo +nightly fuzz run rfb_feed` (alvos `rfb_feed`, `codecs`).

## Contribuindo
Leia [CONTRIBUTING.md](CONTRIBUTING.md) e [GOVERNANCE.md](GOVERNANCE.md). Relate vulnerabilidades conforme [SECURITY.md](SECURITY.md).

## Licença
[Apache-2.0](LICENSE).
