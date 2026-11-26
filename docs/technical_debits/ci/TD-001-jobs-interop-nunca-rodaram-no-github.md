---
id: TD-001
titulo: Jobs de interop nunca rodaram no GitHub Actions
componente: ci
tipo: lacuna-de-teste
prioridade: P0
status: aberto
fase-alvo: v0.3
criado-em: 2026-11-26
atualizado-em: 2026-11-26
---

# TD-001: Jobs de interop nunca rodaram no GitHub Actions

## Contexto
Os tres jobs passaram apenas em container local reproduzindo os mesmos passos. As branches `fase-1` e `fase-2` nao foram integradas na `main`.

## Impacto
Os aceites da v0.2 (TigerVNC a 29,9 FPS) e da v0.3 (VeNCrypt contra Xvnc) nao tem prova reproduzivel em CI. Diferencas de runner (pacotes, permissoes, containers) podem quebrar os jobs.

## Onde
- `.github/workflows/ci.yml` (jobs `interop-reference`, `wayland`, `interop-tls`)
- `ci/interop/run.sh`, `ci/wayland/run.sh`, `ci/tls/run.sh`

## Proposta de solucao
1. Integrar o trabalho das fases na branch principal.
2. Rodar o workflow no GitHub e corrigir diferencas de ambiente.
3. Tornar os tres jobs obrigatorios na protecao de branch.

## Criterio de conclusao
- [ ] `interop-reference` verde no GitHub
- [ ] `wayland` verde no GitHub
- [ ] `interop-tls` verde no GitHub

## Referencias
- Origem: `PLANO.md` (branch `fase-2`, commit 9a0df7e), secao "Progresso consolidado (apos a v0.3)".

## Historico
- 2026-11-26: registrado a partir da analise das fases 0 a 3.
- 2026-11-26: reavaliado. **Impossivel nesta sessao:** rodar no GitHub Actions exige push e execucao no repositorio remoto, que dependem de autorizacao explicita do mantenedor (nenhum commit ou push foi autorizado). Como mitigacao, os scripts `ci/x11` e `ci/netem` foram executados localmente em container Linux (podman) com a mesma imagem base dos jobs.
