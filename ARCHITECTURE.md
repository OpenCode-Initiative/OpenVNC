# Arquitetura

```
 Aplicações (clients/desktop, clients/cli, servers/reference, bindings/*)
        │
 openvnc-ffi ── C ABI estável (handles opacos)
        │
 ┌───────────── Core Rust ──────────────┐
 │ openvnc-client                       │  sessão async (tokio), reconexão
 │ openvnc-rfb        openvnc-protocol  │  protocolos (sans-IO)
 │ openvnc-codecs     openvnc-security  │  encodings / autenticação
 │ openvnc-framebuffer                  │  framebuffer, dirty regions
 │ openvnc-transport                    │  TCP, TLS 1.3, QUIC
 │ openvnc-core                         │  tipos, erros, limites
 └──────────────────────────────────────┘
```

## Regras
- **Protocolos são sans-IO:** parsers e máquinas de estado operam sobre bytes; o transporte é injetado. Isso permite testes por fixtures e fuzzing.
- **Dependências apontam para baixo:** todo crate pode depender de `openvnc-core`; nenhum crate de base depende de UI ou de SO.
- **Limites obrigatórios:** todo campo de tamanho vindo da rede passa por `openvnc_core::check_limit`.
- **Erros:** `openvnc_core::Error` (`thiserror`); sem `panic!`/`unwrap` em caminhos alimentados pela rede.
- **Logs:** `tracing`; nunca senhas, chaves ou pixels.
- **`unsafe`:** negado no workspace; liberado só em `openvnc-ffi` e em módulos de SO, com comentário `// SAFETY:`.

- **Sessão:** `openvnc-client` roda a rede numa task tokio; a UI envia `Command` por canal, recebe `SessionEvent` e lê o quadro em `Arc<Mutex<SharedFrame>>` (com damage para upload parcial de textura). A UI nunca bloqueia em I/O.

Detalhes: [docs/architecture.md](docs/architecture.md).
