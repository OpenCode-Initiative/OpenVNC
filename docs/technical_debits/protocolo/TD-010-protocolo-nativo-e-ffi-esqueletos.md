---
id: TD-010
titulo: openvnc-protocol e openvnc-ffi sao esqueletos vazios
componente: protocolo
tipo: funcionalidade-pendente
prioridade: P1
status: resolvido
fase-alvo: v0.4
criado-em: 2026-11-26
atualizado-em: 2026-11-26
---

# TD-010: openvnc-protocol e openvnc-ffi sao esqueletos vazios

## Contexto
Os crates existem desde a Fase 0 apenas com a constante de versao. A especificacao RFC nao foi escrita.

## Impacto
Bloqueia a Fase 4 (protocolo nativo, QUIC, video, clipboard) e a Fase 5 (C ABI e bindings).

## Onde
- `core/crates/openvnc-protocol/src/lib.rs`
- `core/crates/openvnc-ffi/src/lib.rs`
- `docs/RFC/` (vazio), `docs/protocol-native.md`, `docs/abi/c-api.md`

## Proposta de solucao
1. Escrever a RFC em `docs/RFC/` (framing, mensagens, capabilities, limites).
2. Implementar o framing sans-IO com fuzzing.
3. Definir a C ABI com handles opacos e cbindgen.

## Criterio de conclusao
- [x] RFC v0 publicada para revisao
- [x] Framing implementado com testes e alvo de fuzzing

## Referencias
- Origem: `PLANO.md` (branch `fase-2`, commit 9a0df7e), secao "Progresso consolidado (apos a v0.3)".

## Historico
- 2026-11-26: registrado a partir da analise das fases 0 a 3.
- 2026-11-26: framing sans-IO e todas as mensagens implementados em `openvnc-protocol` (com clipboard, arquivos, limites e testes), RFC em `docs/RFC/0001-protocolo-nativo.md` e C ABI inicial em `openvnc-ffi` (`include/openvnc.h`). Falta: servidor e cliente usando o protocolo (ver TD-005) e geracao do header via cbindgen.
- 2026-11-26: servidor e cliente usam o protocolo (ver TD-005). Em vez de cbindgen (ferramenta externa no build), o header manual ganhou o teste `header_em_sincronia`, que falha se uma funcao exportada faltar no header, se o header declarar funcao inexistente ou se um codigo de retorno divergir. Resolvido.
