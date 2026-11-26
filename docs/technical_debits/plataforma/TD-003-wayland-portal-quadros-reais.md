---
id: TD-003
titulo: Wayland: portal com quadros reais e entrada RemoteDesktop nao testados
componente: plataforma
tipo: lacuna-de-teste
prioridade: P1
status: aberto
fase-alvo: v0.4
criado-em: 2026-11-26
atualizado-em: 2026-11-26
---

# TD-003: Wayland: portal com quadros reais e entrada RemoteDesktop nao testados

## Contexto
O caminho PipeWire, servidor, vncviewer foi verificado com um no `videotestsrc` (`OPENVNC_PIPEWIRE_NODE`, que pula o portal). O xdg-desktop-portal-wlr 0.7 exige GPU, nao entrega quadros no container e nao implementa RemoteDesktop.

## Impacto
O uso real (GNOME/KDE com portal) nao tem evidencia de funcionamento, nem para captura nem para entrada.

## Onde
- `core/crates/openvnc-platform/src/wayland.rs`
- `ci/wayland/run.sh`

## Proposta de solucao
1. Testar em GNOME e KDE com GPU (maquina fisica ou VM com virgl).
2. Validar o fluxo de consentimento do portal e a restauracao de sessao.
3. Validar entrada de teclado e mouse via RemoteDesktop.

## Criterio de conclusao
- [ ] Quadros reais via portal no GNOME
- [ ] Quadros reais via portal no KDE
- [ ] Entrada RemoteDesktop verificada ponta a ponta

## Referencias
- Origem: `PLANO.md` (branch `fase-2`, commit 9a0df7e), secao "Progresso consolidado (apos a v0.3)".

## Historico
- 2026-11-26: registrado a partir da analise das fases 0 a 3.
- 2026-11-26: reavaliado. **Impossivel neste ambiente:** o caminho portal-wlr (sway headless) ja e coberto pelo job `wayland` do CI, mas os criterios pedem GNOME e KDE. O xdg-desktop-portal-gnome e o -kde exigem gnome-shell/kwin com sessao systemd de usuario e mostram um seletor de tela que pede consentimento interativo na primeira sessao (sem restore token previo). Isso nao roda de forma automatizada no Windows desta sessao nem na VM do podman (2 GB de RAM, sem systemd). Precisa de uma maquina Linux com GNOME e outra com KDE, com alguem para aceitar o dialogo uma vez.
- 2026-11-26: nova tentativa no podman: a pilha GNOME (mutter 48.7, gnome-shell, xdg-desktop-portal-gnome, Debian trixie) exige 564 pacotes numa VM de 2 GB compartilhada, e o portal continua exigindo o clique no dialogo de consentimento na primeira sessao, sem dispositivo de entrada no modo headless. Impossibilidade mantida.
