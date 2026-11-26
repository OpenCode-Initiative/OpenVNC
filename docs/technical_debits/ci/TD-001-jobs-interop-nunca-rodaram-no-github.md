---
id: TD-001
titulo: Jobs de interop nunca rodaram no GitHub Actions
componente: ci
tipo: lacuna-de-teste
prioridade: P0
status: resolvido
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
- [x] `interop-reference` verde no GitHub
- [x] `wayland` verde no GitHub
- [x] `interop-tls` verde no GitHub

## Referencias
- Origem: `PLANO.md` (branch `fase-2`, commit 9a0df7e), secao "Progresso consolidado (apos a v0.3)".

## Historico
- 2026-11-26: registrado a partir da analise das fases 0 a 3.
- 2026-11-26: reavaliado. **Impossivel nesta sessao:** rodar no GitHub Actions exige push e execucao no repositorio remoto, que dependem de autorizacao explicita do mantenedor (nenhum commit ou push foi autorizado). Como mitigacao, os scripts `ci/x11` e `ci/netem` foram executados localmente em container Linux (podman) com a mesma imagem base dos jobs.
- 2026-11-26: run 45768367111 (commit 74796aa) falhou em fmt, clippy (`map_or` em x11.rs), deny (rust-toolchain.toml pedia toolchain musl no container), audit (RUSTSEC-2025-0008 no openh264-sys2 0.6) e x11-shm (os dois testes X11 rodavam em paralelo e o de Damage desenhava na tela durante a comparacao). Corrigido no commit 4a5faf7 (openh264 0.9, `rust-version: stable` no deny, `--test-threads=1`). Run 45769347328: todos os jobs verdes, inclusive interop-reference, interop-tigervnc, interop-tightvnc, interop-tls, wayland e x11-shm.
