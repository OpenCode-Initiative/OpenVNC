---
id: TD-008
titulo: Renderer proprio sem backends nativos por SO
componente: cliente
tipo: divida-tecnica
prioridade: P2
status: resolvido
fase-alvo: v0.4
criado-em: 2026-11-26
atualizado-em: 2026-11-26
---

# TD-008: Renderer proprio sem backends nativos por SO

## Contexto
A v0.1 foi aceita com 98 a 111 MB de RAM ociosa (meta: 100 MB), quase tudo do driver OpenGL. O renderer `OPENVNC_RENDERER=native` (softbuffer) caiu para 12 MB privados, mas nao e o padrao, e a GUI de conexao continua em egui.

## Impacto
O modo padrao ainda carrega o driver GL. Faltam os backends planejados (GDI/Direct2D, X11 SHM, wl_shm, CALayer) e a escrita direta em BGRA.

## Onde
- `clients/desktop/src/native.rs` (winit + softbuffer)
- Detalhes: `docs/renderer-proprio.md`

## Proposta de solucao
Seguir a proposta de `docs/renderer-proprio.md` e tornar o renderer nativo o padrao da sessao.

## Criterio de conclusao
- [x] Renderer nativo como padrao em Windows e Linux
- [x] RAM ociosa abaixo de 100 MB medida e documentada

## Referencias
- Origem: `PLANO.md` (branch `fase-2`, commit 9a0df7e), secao "Progresso consolidado (apos a v0.3)".

## Historico
- 2026-11-26: registrado a partir da analise das fases 0 a 3.
- 2026-11-26: Renderer nativo virou o padrao quando ha host na linha de comando (OPENVNC_RENDERER=glow|wgpu volta para egui). Falta a tela de conexao fora do egui e a medicao de RAM documentada.
- 2026-11-26: medicao no Windows 11 (build release, renderer nativo softbuffer, sessao ativa com o servidor de referencia em TestPattern 800x600 a ~30 fps), amostras a cada 5 s por 30 s: working set 35,6 a 36,1 MB, memoria privada 11,0 a 11,6 MB, estavel. Bem abaixo da meta de 100 MB (o egui+glow ficava em 98 a 111 MB). A tela de conexao continua no egui, mas so e aberta sem host na linha de comando, fora da sessao; isso nao afeta o criterio. Resolvido.
