# Renderer próprio para o cliente desktop (trabalho futuro)

Status: **planejado**. Decidido ao encerrar a v0.1, que foi aceita com a RAM ociosa acima da meta.

## Motivação

O critério da v0.1 é RAM ociosa ≤ 100 MB. No Windows 11 (GPU AMD Radeon 740M, renderer glow), as medições foram estas:

| Situação | Privada | Working set |
|---|---|---|
| Janela aberta, sem sessão | ~96 MB | ~87 MB |
| Sessão ativa, sem enviar a imagem para a textura (teste) | ~102 MB | ~95 MB |
| Sessão ativa, normal (TigerVNC 1024x768) | 98–111 MB | 98–105 MB |

Para onde vai a memória:

- **Driver OpenGL da AMD (`atio6axx.dll`):** cerca de 62 MB só da imagem da DLL, mais heaps internos. O executável do OpenVNC ocupa ~10 MB.
- **Textura do framebuffer:** uma imagem de 3 MB (1024x768 RGBA) custa 5–10 MB privados, porque o driver guarda cópias em memória de sistema.
- **Variação:** a medição é bimodal (~98 MB ou ~107 MB) entre execuções idênticas, o que indica alocação do driver.

O que já foi tentado, sem ganho:

- `wgpu`: Vulkan ~360 MB; DirectX 12 ~548 MB privados.
- `NvOptimusEnablement`: o driver AMD continua carregado, porque a janela está no monitor da iGPU.
- `with_drag_and_drop(false)`: diferença não mensurável.

Conclusão: com egui + OpenGL, a meta fica dentro da variação do driver. O código da aplicação ocupa ~15–25 MB.

## Proposta

Separar "desenhar o framebuffer remoto" de "desenhar a UI":

1. **Framebuffer remoto sem GPU.**
   - Windows: `StretchDIBits`/`SetDIBitsToDevice` (GDI) direto do buffer BGRA já decodificado, apenas nos retângulos de damage. Opção alternativa: Direct2D com `ID2D1Bitmap` (`CopyFromMemory` parcial).
   - Linux X11: `XShmPutImage` (MIT-SHM).
   - Wayland: `wl_shm` buffer com `damage_buffer`.
   - macOS: `CGImage`/`CALayer.contents` com `IOSurface`.
2. **Formato de pixel nativo.** O decodificador escreve direto em BGRA (Windows/X11), sem conversão para RGBA nem cópia para `ColorImage`. Isso elimina a cópia extra por quadro em `sync_texture`.
3. **UI leve.**
   - Barra de ferramentas e diálogos (conectar, senha, escala) com controles nativos ou desenhados em GDI.
   - Outra opção: abrir o egui só nas telas sem sessão (conexão), que hoje já ficam em ~96 MB. Sem contexto GL durante a sessão, essa memória sai.
4. **Janela com `winit` puro** (ou `windows-rs`), mantendo:
   - a tradução de teclado de `clients/desktop/src/input.rs`, a ser adaptada de `egui::Event` para eventos winit;
   - o ponteiro, a escala Fit/Native e o foco/`release_all`.
5. **Escala:** GDI `SetStretchBltMode(HALFTONE)` para Fit; 1:1 sem escala no modo Native.

## Arquitetura

- Novo trait em `clients/desktop`: `trait Presenter { fn resize(..); fn present(&mut self, fb: &Framebuffer, damage: &[Rect]); }`, com `GdiPresenter`, `X11ShmPresenter` etc. O `openvnc-client` não muda: continua expondo `frame()` com `fb`, `damage` e `generation`.
- Feature/flag de seleção: `OPENVNC_RENDERER=native|glow|wgpu`. O padrão passa a ser `native` quando estiver estável; o glow fica como fallback.

## Critérios de aceite

- Windows, 1024x768, sessão ativa e tela parada: privada ≤ 60 MB e working set ≤ 60 MB, em 5 execuções seguidas sem variação bimodal.
- CPU com tela parada ~0%, sem redesenho sem damage.
- Sem regressão nos testes de teclado (`input.rs`) nem no E2E de GUI (Xvfb + xdotool; Windows com SendInput).
- Os mesmos números em Linux X11 (Xvfb) medidos no CI.

## Onde entra no plano

Fase 2 (v0.2, "otimização gráfica"), junto com o FPS adaptativo e os benchmarks de RAM. Ver `PLANO.md`.
