---
id: TD-007
titulo: Tight sem JPEG no cliente
componente: cliente
tipo: funcionalidade-pendente
prioridade: P3
status: resolvido
fase-alvo: v0.4
criado-em: 2026-11-26
atualizado-em: 2026-11-26
---

# TD-007: Tight sem JPEG no cliente

## Contexto
O Tight suporta fill e basic (copy/palette/gradient). JPEG nao e suportado, por isso os niveis de qualidade (-32 a -23) nao sao anunciados.

## Impacto
Em redes lentas e conteudo fotografico, servidores como TigerVNC entregariam muito menos bytes com JPEG.

## Onde
- `core/crates/openvnc-codecs/src/lib.rs` (decoder Tight)

## Proposta de solucao
1. Adicionar decoder JPEG de crate auditada (sem codec proprio).
2. Anunciar os pseudo-encodings de qualidade.
3. Incluir o caminho JPEG no alvo de fuzzing `codecs`.

## Criterio de conclusao
- [ ] Tight JPEG decodificado contra Xvnc
- [ ] Fuzzing cobrindo o caminho JPEG

## Referencias
- Origem: `PLANO.md` (branch `fase-2`, commit 9a0df7e), secao "Progresso consolidado (apos a v0.3)".

## Historico
- 2026-11-26: registrado a partir da analise das fases 0 a 3.
- 2026-11-26: subtipo JPEG do Tight decodificado com jpeg-decoder (limite de 16 MiB, dimensoes conferidas contra o retangulo, RGB e tons de cinza); cliente anuncia qualidade JPEG nivel 8 (-24). Teste de JPEG corrompido adicionado.
