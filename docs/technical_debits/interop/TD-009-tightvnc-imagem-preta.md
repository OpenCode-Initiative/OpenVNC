---
id: TD-009
titulo: TightVNC 2.x no Windows entrega imagem preta
componente: interop
tipo: bug-conhecido
prioridade: P3
status: aberto
fase-alvo: v1.0
criado-em: 2026-11-26
atualizado-em: 2026-11-26
---

# TD-009: TightVNC 2.x no Windows entrega imagem preta

## Contexto
Contra TightVNC 2.x (Windows, RFB 3.8, auth None) o screenshot 4480x1440 veio todo preto. Um cliente Raw independente recebeu o mesmo, entao a suspeita recai no servidor (sessao ou captura), nao no decoder.

## Impacto
Resultado inconclusivo na matriz de interoperabilidade para um servidor alvo da v1.0.

## Onde
- `docs/compatibility.md` (secao TightVNC 2.x)

## Proposta de solucao
1. Repetir com sessao interativa ativa e com um unico monitor.
2. Documentar a configuracao do TightVNC que resolve, ou confirmar como limitacao do servidor.

## Criterio de conclusao
- [ ] Causa identificada e registrada em `docs/compatibility.md`

## Referencias
- Origem: `PLANO.md` (branch `fase-2`, commit 9a0df7e), secao "Progresso consolidado (apos a v0.3)".

## Historico
- 2026-11-26: registrado a partir da analise das fases 0 a 3.
- 2026-11-26: reavaliado. **Impossivel nesta sessao:** o TightVNC 2.x nao esta instalado nesta maquina, e instala-lo cria um servico do Windows que exporia a tela real. Isso exige autorizacao do usuario, que nao foi dada. A reproducao continua pendente (P3, v1.0).
