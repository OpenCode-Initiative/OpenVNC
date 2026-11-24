# Matriz de compatibilidade

| Produto | RFB | Status |
|---|---|---|
| TigerVNC (Xvnc, Linux) | 3.3 / 3.7 / 3.8 | Verificado manualmente (ver abaixo); passos do job de CI `interop-tigervnc` executados em Ubuntu 24.04 (container) |
| TightVNC (Xtightvnc 1.3, Linux) | 3.3 / 3.7 / 3.8 | Verificado: imagem, auth, teclado/mouse pela GUI; job de CI `interop-tightvnc` |
| TightVNC 2.x (Windows) | 3.8 | Conecta, `info` e screenshot; a imagem veio preta (ver ressalva) |
| openvnc-server (referência) | 3.8 | Verificado: vncviewer do TigerVNC a 30 FPS; job de CI `interop-reference` |
| RealVNC | 3.8 | posterior |
| x11vnc | 3.8 | planejado |
| macOS Screen Sharing | 3.889 | planejado |

## Testes manuais contra servidores reais (v0.1)

**TigerVNC** (Xvnc em container Podman, Debian):

- RFB 3.8: None e VNC Auth funcionam; uma senha errada é rejeitada com o motivo enviado pelo servidor. O servidor escolheu ZRLE.
- RFB 3.3 e 3.7: forçadas por um proxy que reescreve o banner do servidor real. None e VNC Auth funcionam e uma senha errada é rejeitada.
- Imagem: a captura confere com a tela do servidor.
- Entrada:
  - Teclado: `openvnc type --at X,Y` digitou `Ola, OpenVNC! 123 @#$%&*()[]{}~^` + Return num xterm, com o texto correto.
  - Mouse: no desktop, clique e movimento chegam ao servidor.
- Reconexão: com o servidor derrubado e recriado durante a sessão, o desktop registra `sessao perdida retrying=true` e volta a `sessao estabelecida` em cerca de 3,6 s, sem crash. Fechar a janela encerra limpo.

**TightVNC 1.3** (`tightvncserver` do Debian, em container):

- RFB 3.8 nativo; 3.3 e 3.7 via o proxy de banner. Em todas, None e VNC Auth funcionam e uma senha errada é rejeitada. O servidor escolheu Hextile.
- Imagem correta, incluindo o fundo pontilhado do X.
- O job `interop-tightvnc` foi executado localmente em Ubuntu 24.04 e passou.

**Entrada pela GUI, ponta a ponta** (desktop Linux sob Xvfb, com xdotool digitando na janela do OpenVNC):

- Contra TightVNC e TigerVNC, `Via GUI: Xyz 42 #&*{}`, Return e Ctrl+U chegaram corretos ao xterm remoto.
- O Ctrl+U apagou a linha, o que confirma que os modificadores funcionam.
- A renderização local confere com a captura do servidor.
- No Windows 11, com entrada sintética do sistema (SendInput/SendKeys) na janela do OpenVNC, `WinTeste 42 #&` + Enter chegou correto ao xterm do TigerVNC.

**Fuzzing:** os passos do job `fuzz-build` rodaram com nightly e cargo-fuzz 0.13.2. Sem crashes em 60 s por alvo (`rfb_feed`: 977 mil execuções; `codecs`: 1,88 milhão).

**TightVNC 2.x** (Windows, RFB 3.8, auth None):

- `info` e screenshot (4480x1440) funcionam; o servidor escolheu Hextile.
- Ressalva: a imagem veio toda preta. Um cliente Raw independente recebeu o mesmo preto, então é o servidor que envia assim (sessão/captura), não um erro de decodificação.
- TightVNC recusa conexões de loopback por padrão; use o IP da LAN.
- Visualizar o próprio desktop cria um laço de realimentação e não serve para medir ociosidade.

## Métricas do cliente desktop (Windows 11, TigerVNC 1024x768, tela quase parada)

| Métrica | Alvo v0.1 | Medido (renderer glow, padrão) |
|---|---|---|
| Início até sessão estabelecida | ≤ 2 s | 0,33 s (janela em ~0,7 s) |
| RAM ociosa | ≤ 100 MB | 98–105 MB working set / ~110 MB privados — aceito: ~62 MB são do driver OpenGL da AMD (`atio6axx.dll`); sem sessão, 87 MB WS |
| CPU com tela parada | ~0% | 0–31 ms de CPU em 10 s (com `xclock` ativo) |

Com `OPENVNC_RENDERER=wgpu` (Vulkan) o uso sobe para cerca de 360 MB, quase tudo do driver. Por isso glow é o padrão.

## Encodings do cliente (v0.2)

- Raw, CopyRect, Hextile, ZRLE.
- Tight: fill, basic com filtros copy/palette/gradient. **JPEG não é suportado** e por isso não é anunciado (sem `-32..-23`). O Xvnc foi verificado com Tight.
- Pseudo-encodings: Cursor (-239), DesktopSize (-223) e ExtendedDesktopSize (-308). O redimensionamento via `xrandr` no Xvnc foi verificado.

## VeNCrypt (v0.3)

| Servidor | Subtipo | Resultado |
|---|---|---|
| TigerVNC Xvnc (container) | X509Vnc | ok: TLS 1.3 com pin, senha errada recusada, pin errado recusado, sem TLS recusado, screenshot 320x200 |
| openvnc-server | X509Plain (pareamento), X509Vnc | ok, incluindo dispositivo revogado recusado |
