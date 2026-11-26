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

**Status v0.2:** concluída, com ressalvas de teste nos backends (abaixo). Aceite verificado localmente em Xvfb, num container com os mesmos passos do job `interop-reference` (que ainda não rodou no GitHub): o vncviewer do TigerVNC recebe o test-pattern a 29,9 FPS com ~3,5% de CPU no servidor.

- Backends: test-pattern (todas as plataformas), X11 (GetImage + XTest, sem `unsafe`), Windows, Wayland e macOS:
  - **Windows**: DXGI Desktop Duplication (padrão) com GDI BitBlt de reserva (`OPENVNC_CAPTURE=gdi`) + SendInput. DXGI testado nesta máquina (teste `#[ignore]` `captures_primary_output`: 10 quadros em ~0,31 s, sem inspecionar conteúdo).
  - **Wayland** (feature `wayland`, exige `libpipewire-0.3-dev` e clang): portal RemoteDesktop+ScreenCast (cai para ScreenCast puro se não houver RemoteDesktop) + PipeWire; entrada pelo portal RemoteDesktop. Testado em container (`ci/wayland/run.sh`, job `wayland`): o caminho PipeWire → servidor → vncviewer foi verificado de ponta a ponta com um nó `videotestsrc` (`OPENVNC_PIPEWIRE_NODE`, que pula o portal). A sessão do portal foi exercitada até o backend, mas o xdg-desktop-portal-wlr 0.7 exige GPU (`/dev/dri`/gbm) e não entrega quadros no container; **portal com quadros reais e entrada RemoteDesktop não foram testados** (o portal-wlr não tem RemoteDesktop; precisa de GNOME/KDE).
  - **macOS**: CoreGraphics `CGDisplayCreateImage` + `CGEventPost`, FFI direta. **Só compilado** (clippy para `aarch64-apple-darwin` e job `macos-build`); nunca rodou num Mac. Pendente: migrar para ScreenCaptureKit (`CGDisplayCreateImage` está obsoleto no macOS 15) e testar permissões de Gravação de Tela/Acessibilidade.
  - Fica para depois: MIT-SHM/Damage no X11 (hoje GetImage do quadro inteiro).
- Cliente: Tight (sem JPEG), Cursor, DesktopSize e ExtendedDesktopSize; testado contra o Xvnc, inclusive `xrandr`.
- Benchmarks (`cargo bench -p openvnc-codecs`, 1280x720): encode raw 2,4 ms / hextile 2,5 ms / zrle 3,2 ms; decode 0,94 / 0,15 / 1,37 ms.
- Renderer nativo (`OPENVNC_RENDERER=native openvnc-desktop host`): winit + softbuffer, sem GL. Mediu 24 MB de working set e 12 MB privados no Windows com animação, contra 98–111 MB do glow. A GUI de conexão continua em egui.

## Fase 3 — v0.3 Segurança e transporte moderno

1. TLS 1.3 (rustls) e VeNCrypt para servidores que suportam; validação estrita de certificado; pinning/TOFU para auto-assinados; **sem downgrade silencioso**.
2. QUIC (quinn): handshake e streams separados (controle, entrada, gráficos, metadados) — ainda sem lógica de aplicação.
3. Pareamento de dispositivos, revogação, logs de auditoria no servidor.
4. Medir QUIC vs TCP antes de declarar ganho.

**Status v0.3:** concluída, com ressalvas. Verificado no Windows e em container Linux (fmt, clippy `-D warnings`, testes, `cargo deny`):

- VeNCrypt (tipo 19) com X509None/X509Vnc/X509Plain sobre TLS 1.3 (rustls). Cliente: `--tls`, `--pin SHA256`, `--tofu`/`--tofu-accept` (known_hosts), `--ca`. Com TLS pedido, um servidor sem VeNCrypt é recusado (sem downgrade). Certificado trocado gera erro "CERTIFICADO MUDOU".
- Interop: cliente `openvnc` x Xvnc do TigerVNC com `-SecurityTypes X509Vnc` (TLS 1.3, senha certa/errada, pin errado, sem TLS recusado). Script `ci/tls/run.sh` e job `interop-tls`, que rodou em container local e ainda não no GitHub.
- Servidor de referência: `--tls`, `--require-tls`, certificado autoassinado gerado no primeiro uso, `fingerprint`; `--pairing` com `pair add/list/revoke` (token de 256 bits, guarda só o SHA-256); log de auditoria JSON lines (conexão, TLS, auth ok/falha com motivo, revogado, desconexão).
- QUIC (quinn): handshake e 4 streams (controle, entrada, gráficos, metadados) só como transporte, com testes. **Não** está ligado ao servidor nem ao cliente.
- Medição (`cargo run --release -p openvnc-transport --example bench_transport`), loopback:

| | Windows: vazão | RTT p50 / p99 | Linux (container): vazão | RTT p50 |
|---|---|---|---|---|
| TCP | 26–29 Gbit/s | ~30 µs / ~77 µs | 21,8 Gbit/s | 64 µs |
| TLS 1.3 | 15,5–16,3 Gbit/s | 32–42 µs / ~95 µs | 18,7 Gbit/s | 71 µs |
| QUIC | 2,3–2,4 Gbit/s | 44–48 µs / 99–128 µs | 3,3 Gbit/s | 132 µs |
| QUIC: entrada com gráficos saturando | — | ~42 µs / 10–11 ms | — | 172 µs (p99 2,3 ms) |

  Conclusão: **em loopback o QUIC não traz ganho**; custa CPU e vazão. Não foi medido em rede real com perda e latência, onde o benefício esperado (sem head-of-line blocking entre streams) apareceria. Também não há o teste equivalente de "entrada sob carga" em TCP, porque falta o framing próprio, que fica para a Fase 4.
- Pendências: o cliente desktop compila com TLS, mas ainda não tem UI para pin/TOFU; o listener QUIC fica para quando houver protocolo nativo.

## Progresso consolidado (após a v0.3)

Fases 0 a 3 entregues (detalhes nos status acima). As pendências agora ficam registradas em [docs/technical_debits/](docs/technical_debits/README.md), uma por arquivo, com status e critério de conclusão.

**Status em 2026-11-26:** resolvidos TD-006 (UI TLS no desktop), TD-007 (JPEG no Tight) e TD-010 (protocolo nativo e C ABI). Em andamento: TD-002 (macOS: permissões TCC feitas, ScreenCaptureKit exige Mac), TD-004 (X11), TD-005 (QUIC integrado; falta medir com netem) e TD-008 (renderer). Dependem de infraestrutura que este ambiente não tem: TD-001 (GitHub Actions), TD-003 (Wayland com GPU) e TD-009 (TightVNC).

## Fase 4 — v0.4 Protocolo nativo OpenVNC

1. Especificação em `docs/RFC/` (linguagem normativa, versionada): header `Version(2) Type(2) Flags(2) Length(4)` big-endian; mensagens CLIENT_HELLO…CLOSE; negociação explícita de capabilities; limites de tamanho. Revisão pública antes de congelar códigos.
2. `openvnc-protocol` cliente/servidor sobre QUIC com fallback TCP+TLS; descoberta por endpoint próprio (nunca interpretar banner RFB).
3. Vídeo via codec consolidado (H.264, depois AV1) para regiões de movimento; tiles lossless para texto.
4. Clipboard e transferência de arquivos básica.

**Status:** itens 1 a 4 entregues (RFC em `docs/RFC/0001-protocolo-nativo.md`, servidor com `--native`, cliente `NativeClient` e `openvnc native` na CLI, testes QUIC e TCP+TLS em loopback). Item 3 entregue com H.264 (openh264, feature `h264`, 13,5x menos banda que zlib em cena com movimento; ver TD-011). AV1 segue reservado.

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
