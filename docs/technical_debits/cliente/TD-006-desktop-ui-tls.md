---
id: TD-006
titulo: Cliente desktop sem UI para TLS (pin, TOFU, usuario/dispositivo)
componente: cliente
tipo: funcionalidade-pendente
prioridade: P1
status: resolvido
fase-alvo: v0.4
criado-em: 2026-11-26
atualizado-em: 2026-11-26
---

# TD-006: Cliente desktop sem UI para TLS (pin, TOFU, usuario/dispositivo)

## Contexto
O desktop compila com TLS, mas so a CLI expoe pin, TOFU, CA e credenciais de dispositivo pareado.

## Impacto
O usuario da GUI nao consegue usar VeNCrypt nem pareamento, que sao os modos seguros do servidor (`--require-tls --pairing`).

## Onde
- `clients/desktop/src/main.rs`
- Referencia de comportamento: `clients/cli/src/main.rs` (`--tls`, `--pin`, `--tofu`, `--ca`, `--user`)

## Proposta de solucao
1. Dialogo de primeira conexao mostrando a impressao SHA-256 (TOFU).
2. Alerta bloqueante quando o certificado mudar.
3. Campos de usuario/dispositivo e token.

## Criterio de conclusao
- [x] Conexao TLS com TOFU pela GUI
- [x] Certificado trocado bloqueia a conexao com aviso claro
- [x] Conexao a servidor com `--pairing` pela GUI

## Referencias
- Origem: `PLANO.md` (branch `fase-2`, commit 9a0df7e), secao "Progresso consolidado (apos a v0.3)".

## Historico
- 2026-11-26: registrado a partir da analise das fases 0 a 3.
- 2026-11-26: GUI ganhou seletor de seguranca (TOFU, CA publica, pin SHA-256, CA PEM, sem TLS), campo de dispositivo/token, dialogo de primeira conexao com a impressao e alerta bloqueante de certificado trocado (sem opcao de ignorar). Renderer nativo aceita OPENVNC_TLS e OPENVNC_USER. Validacao manual contra servidor real pendente.
