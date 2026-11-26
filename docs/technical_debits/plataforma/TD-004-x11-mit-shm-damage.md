---
id: TD-004
titulo: X11 captura o quadro inteiro com GetImage
componente: plataforma
tipo: divida-tecnica
prioridade: P2
status: resolvido
fase-alvo: v0.4
criado-em: 2026-11-26
atualizado-em: 2026-11-26
---

# TD-004: X11 captura o quadro inteiro com GetImage

## Contexto
A captura X11 usa `GetImage` da tela inteira a cada quadro, sem `unsafe`. MIT-SHM e Damage ficaram para depois.

## Impacto
Copia o framebuffer inteiro pelo socket do X a cada quadro: mais CPU e latencia em resolucoes altas, e o diff de tiles processa a tela toda.

## Onde
- `core/crates/openvnc-platform/src/x11.rs` (chamada `get_image`)

## Proposta de solucao
1. Usar MIT-SHM (`ShmGetImage`) com fallback para GetImage quando indisponivel.
2. Usar a extensao Damage para capturar so as regioes alteradas.
3. Medir antes e depois.

## Criterio de conclusao
- [x] Captura via MIT-SHM com fallback
- [x] Regioes vindas do Damage alimentam o diff
- [x] Benchmark mostrando reducao de CPU em 1920x1080 ou maior

## Referencias
- Origem: `PLANO.md` (branch `fase-2`, commit 9a0df7e), secao "Progresso consolidado (apos a v0.3)".

## Historico
- 2026-11-26: registrado a partir da analise das fases 0 a 3.
- 2026-11-26: Damage (BoundingBox) implementado: so o retangulo alterado e lido com GetImage, com fallback para quadro completo sem a extensao. MIT-SHM pendente: exige shmat/mmap (unsafe). Benchmark exige servidor X real (impossivel neste ambiente Windows).
- 2026-11-26: MIT-SHM 1.2 implementado em `x11.rs` (ShmCreateSegment + mmap somente leitura, recriado no resize, fallback para GetImage se a extensao faltar, se o X for remoto, se `OPENVNC_X11_NO_SHM` estiver definido (depois trocado por opt-in `OPENVNC_X11_SHM=1`) ou se ShmGetImage falhar). Teste `shm_igual_getimage_e_mais_rapido` (script `ci/x11/run.sh`, job `x11-shm` no CI) passou em Xvfb 1920x1080 no podman: SHM e GetImage produzem pixels identicos em tela inteira e em retangulo parcial. Tempo por quadro (media de 30): primeira rodada sem aquecimento 11,7 ms SHM contra 6,7 ms GetImage (vies de page fault, corrigido com aquecimento); segunda rodada 16,7 ms contra 16,9 ms. **Empate dentro do ruido:** no Xvfb o framebuffer ja esta na RAM e o socket local e barato, e o custo dominante e a conversao por pixel, igual nos dois caminhos. A VM do podman (2 GB, compartilhada com outros containers) e ruidosa demais para medir CPU. O criterio de reducao de CPU continua aberto e precisa de um servidor X real (Xorg com GPU) numa maquina Linux dedicada.
- 2026-11-26: medido o tempo de CPU do processo (utime+stime de `/proc/self/stat`, 120 quadros 1920x1080, com aquecimento, 3 rodadas no podman): MIT-SHM 207/284/208 ticks (20,2/30,6/21,1 ms por quadro) contra GetImage 110/148/170 ticks (11,1/16,4/20,7 ms). **Resultado negativo:** no Xvfb o MIT-SHM nao reduz CPU, ele aumenta (leitura do mapeamento compartilhado mais o ShmGetImage sincrono). Decisao: MIT-SHM passa a ser opt-in (`OPENVNC_X11_SHM=1`); o padrao fica Damage + GetImage, o caminho de menor CPU medido. Essa impossibilidade foi superada pela medicao seguinte.
- 2026-11-26: teste `damage_reduz_cpu` (em `ci/x11/run.sh`, job `x11-shm`): Xvfb 1920x1080, area de 64x64 desenhada no root a cada quadro, 120 quadros, CPU do processo via `/proc/self/stat`. Captura padrao (Damage + GetImage) contra o quadro completo por GetImage (comportamento anterior): 6 contra 145 ticks e 0,42 contra 7,7 ms por quadro; 7 contra 167 ticks e 0,50 contra 9,0 ms. Reducao de CPU de cerca de 20x, com assert no teste. Criterio atendido; item resolvido. O MIT-SHM segue opt-in pelo resultado negativo acima.
