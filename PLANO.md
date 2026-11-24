# OpenVNC — Plano de Ação de Implementação

> Derivado de `CONTEXT.md`. Onde o documento evoluiu (VNC2 cliente leve → OpenVNC comunitário com cliente, servidor de referência e C ABI), este plano adota a **decisão mais recente**.

## Decisões consolidadas

| Tema | Decisão |
|---|---|
| Nome | OpenVNC (VNC2 descartado até checagem de marca) |
| Licença | Apache-2.0, contribuições via DCO |
| Linguagem | Rust (implementação de referência) |
| Interoperabilidade | Especificação de protocolo independente + C ABI (`openvnc-ffi`) |
| Legado | RFB 3.3 / 3.7 / 3.8 (RFC 6143), sem inventar "3.9" |
| Transporte | TCP (legado) → TCP+TLS 1.3 (rustls) → QUIC (quinn); P2P/WebRTC opcional e tardio |
| UI desktop | egui + wgpu + winit |
| Async / logs / config | tokio, tracing, TOML |
| Princípios | Não reinventar RFB, não criar codec nem criptografia própria, sem dependência de nuvem |

## Estrutura alvo (monorepo)

```
docs/ (architecture, protocol-rfb, protocol-native, security, compatibility, abi/c-api, RFC/)
core/crates/
  openvnc-core         tipos: PixelFormat, Rect, eventos, erros
  openvnc-framebuffer  framebuffer, dirty regions, conversão de pixel
  openvnc-rfb          handshake, segurança, mensagens, encodings (cliente e servidor)
  openvnc-codecs       Raw, CopyRect, Hextile, ZRLE, Tight (decoder + encoder)
  openvnc-transport    TCP, TLS, QUIC, reconexão/backoff
  openvnc-security     auth VNC (DES legado), VeNCrypt/TLS, validação de certificados
  openvnc-protocol     protocolo nativo (framing, capabilities)
  openvnc-ffi          C ABI (handles opacos, cbindgen)
clients/desktop, clients/cli   servers/reference   bindings/*   conformance/{protocol-tests,interoperability,fuzzing}
```

## Fase 0 — Fundação do repositório (1–2 semanas)

1. Documentos raiz: `README.md`, `LICENSE` (Apache-2.0), `ARCHITECTURE.md`, `PROTOCOL.md`, `SECURITY.md`, `GOVERNANCE.md`, `CONTRIBUTING.md` (DCO), `CODE_OF_CONDUCT.md`.
2. Workspace Cargo em `core/` com os crates vazios compilando.
3. CI (GitHub Actions): `fmt`, `clippy -D warnings`, `cargo test` em Windows/Linux/macOS, `cargo audit`, `cargo deny` (licenças/advisories).
4. Padrão de erros (`thiserror`) e logs (`tracing`), sem log de senhas/conteúdo de tela.

**Pronto quando:** CI verde nos 3 SOs com workspace vazio.

## Fase 1 — v0.1 Núcleo RFB + cliente legado (MVP)

Ordem de execução (cada item com testes por fixtures de bytes):

1. `openvnc-core`: `PixelFormat`, `Rect`, eventos de teclado (keysyms X11) e mouse.
2. `openvnc-rfb` — **máquina de estados sans-IO** (parser puro sobre `&[u8]`, sem tokio): banner de versão, diferenças 3.3/3.7/3.8, SecurityTypes, SecurityResult (com motivo em 3.8), ClientInit/ServerInit.
3. Autenticação: None e VNC Auth (DES) — este último sinalizado como inseguro na UI.
4. Mensagens cliente: SetPixelFormat, SetEncodings, FramebufferUpdateRequest, KeyEvent, PointerEvent, ClientCutText. Mensagens servidor: FramebufferUpdate, SetColourMapEntries, Bell, ServerCutText.
5. `openvnc-codecs` (P0): Raw, CopyRect, Hextile, ZRLE (flate2 com limite de saída anti-bomba).
6. Regra: só anunciar no SetEncodings o que estiver 100% implementado.
7. `openvnc-transport`: TCP com tokio, timeouts, limite de tentativas e backoff.
8. `openvnc-framebuffer`: buffer reutilizável, dirty tracking, conversão para RGBA.
9. `clients/cli`: conectar e salvar screenshot PNG (valida protocolo antes da GUI).
10. `clients/desktop`: tela de conexão (host:porta), render via textura wgpu com atualização parcial, entrada mouse/teclado, escala/redimensionamento, rede em task separada (UI nunca trava).
11. Alerta explícito para conexão sem criptografia; suporte a túnel SSH documentado.

**Hardening desde o início:** limites de tamanho em todo campo length, aritmética checada, `cargo-fuzz` nos parsers de handshake e encodings, testes com mensagens truncadas/corrompidas.

**Critérios de aceite v0.1:** conecta e opera TigerVNC e TightVNC (3.3/3.7/3.8); inicialização ≤ 2 s; RAM idle ≤ 100 MB; CPU ~0% com tela parada; reconexão/desconexão tratadas sem crash.

**Status v0.1:** concluída. Todos os critérios passaram, exceto a RAM ociosa: 98–111 MB privados no Windows com GPU AMD, quase tudo do driver OpenGL. O usuário aceitou o valor; a correção ficou para a v0.2 ([docs/renderer-proprio.md](docs/renderer-proprio.md)).

## Fase 2 — v0.2 Servidor de referência + otimização gráfica

1. Traits `ScreenCapture` e `InputInjector` com implementações: Windows (DXGI Desktop Duplication / SendInput), Linux X11 (XCB+SHM/Damage, XTest), Wayland (PipeWire/portal), macOS (ScreenCaptureKit/CGEvent, permissões).
2. `servers/reference`: servidor RFB 3.8 (Raw → Hextile/ZRLE), detecção de dirty rects, CopyRect, múltiplos clientes compartilhando o fluxo, config TOML com padrões seguros.
3. Encodings P1 no cliente: Tight, Cursor pseudo-encoding, DesktopSize; P2: ExtendedDesktopSize (multi-monitor).
4. FPS adaptativo (não renderizar com tela parada; agrupar sob movimento intenso).
5. Benchmarks reproduzíveis (`criterion` + cenários fixos) de CPU, RAM, latência.
6. Renderer próprio no cliente desktop (GDI/Direct2D, X11 SHM, wl_shm, CALayer) no lugar de egui+OpenGL durante a sessão, para tirar o driver GL da RAM ociosa. A v0.1 fechou com 98–111 MB privados, contra a meta de 100 MB. Detalhes em [docs/renderer-proprio.md](docs/renderer-proprio.md).

**Aceite:** TigerVNC viewer conecta ao servidor de referência; animação simples a 30 FPS com baixo CPU.

**Status v0.2:** concluída. Aceite verificado em Xvfb (job `interop-reference`): o vncviewer do TigerVNC recebe o test-pattern a 29,9 FPS com ~3,5% de CPU no servidor.

- Backends: test-pattern (todas as plataformas), X11 (GetImage + XTest, sem `unsafe`) e Windows (GDI BitBlt + SendInput, com `unsafe` isolado no módulo). Ficam para depois: DXGI Desktop Duplication, Wayland (portal/PipeWire) e macOS.
- Cliente: Tight (sem JPEG), Cursor, DesktopSize e ExtendedDesktopSize; testado contra o Xvnc, inclusive `xrandr`.
- Benchmarks (`cargo bench -p openvnc-codecs`, 1280x720): encode raw 2,4 ms / hextile 2,5 ms / zrle 3,2 ms; decode 0,94 / 0,15 / 1,37 ms.
- Renderer nativo (`OPENVNC_RENDERER=native openvnc-desktop host`): winit + softbuffer, sem GL. Mediu 24 MB de working set e 12 MB privados no Windows com animação, contra 98–111 MB do glow. A GUI de conexão continua em egui.

## Fase 3 — v0.3 Segurança e transporte moderno

1. TLS 1.3 (rustls) e VeNCrypt para servidores que suportam; validação estrita de certificado; pinning/TOFU para auto-assinados; **sem downgrade silencioso**.
2. QUIC (quinn): handshake e streams separados (controle, entrada, gráficos, metadados) — ainda sem lógica de aplicação.
3. Pareamento de dispositivos, revogação, logs de auditoria no servidor.
4. Medir QUIC vs TCP antes de declarar ganho.

## Fase 4 — v0.4 Protocolo nativo OpenVNC

1. Especificação em `docs/RFC/` (linguagem normativa, versionada): header `Version(2) Type(2) Flags(2) Length(4)` big-endian; mensagens CLIENT_HELLO…CLOSE; negociação explícita de capabilities; limites de tamanho. Revisão pública antes de congelar códigos.
2. `openvnc-protocol` cliente/servidor sobre QUIC com fallback TCP+TLS; descoberta por endpoint próprio (nunca interpretar banner RFB).
3. Vídeo via codec consolidado (H.264, depois AV1) para regiões de movimento; tiles lossless para texto.
4. Clipboard e transferência de arquivos básica.

## Fase 5 — v1.0 Estável e ecossistema

1. `openvnc-ffi` estável (handles opacos, sem tipos Rust expostos, header via cbindgen, versionamento de ABI).
2. Bindings priorizados: C/C++ → Python → Go → C#/Java/Node; exemplos em `examples/`.
3. Suíte de conformidade independente da implementação + matriz pública de interoperabilidade (TigerVNC, TightVNC, RealVNC, x11vnc, macOS Screen Sharing).
4. Empacotamento multiplataforma, documentação completa, release pública.
5. Pós-1.0: cliente Web (WASM), Android, relay/P2P opcional.

## Fora de escopo até v0.4
Áudio remoto, relay/infra central, gerenciamento empresarial, codec próprio, criptografia própria.

## Riscos e mitigações

| Risco | Mitigação |
|---|---|
| Particularidades de servidores reais | Matriz de interoperabilidade com containers (TigerVNC/TightVNC) no CI |
| Parser como superfície de ataque | sans-IO + fuzzing contínuo + limites obrigatórios |
| Captura/injeção dependente de SO (Wayland, macOS) | Traits isoladas; entregar Windows/X11 primeiro |
| Escopo crescendo (cliente + servidor + FFI) | Fases com critérios de aceite; cliente legado antes de tudo |
| Marca/nome | Verificar disponibilidade de "OpenVNC" antes do anúncio público |

## Próximas ações imediatas
1. Criar documentos raiz e `LICENSE`.
2. Criar workspace `core/` com os 8 crates e CI.
3. Implementar o parser de banner/versão RFB com testes de fixture — primeiro PR de código.
