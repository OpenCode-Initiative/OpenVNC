---
id: TD-002
titulo: macOS usa CGDisplayCreateImage obsoleto e nunca rodou num Mac
componente: plataforma
tipo: divida-tecnica
prioridade: P1
status: em-andamento
fase-alvo: v0.4
criado-em: 2026-11-26
atualizado-em: 2026-11-26
---

# TD-002: macOS usa CGDisplayCreateImage obsoleto e nunca rodou num Mac

## Contexto
O backend foi apenas compilado (clippy para `aarch64-apple-darwin` e job `macos-build`). `CGDisplayCreateImage` esta obsoleto no macOS 15.

## Impacto
A captura pode falhar ou ser removida em versoes novas do macOS. Permissoes de Gravacao de Tela e Acessibilidade nao foram validadas, entao o comportamento real e desconhecido.

## Onde
- `core/crates/openvnc-platform/src/macos.rs` (FFI direta para `CGDisplayCreateImage` e `CGEventPost`)

## Proposta de solucao
1. Migrar a captura para ScreenCaptureKit (`SCStream`).
2. Detectar permissoes ausentes (TCC) e orientar o usuario.
3. Testar em Mac real (Apple Silicon e, se possivel, Intel).

## Criterio de conclusao
- [ ] Captura via ScreenCaptureKit funcionando no macOS 14 e 15
- [ ] Entrada via CGEvent verificada com permissao de Acessibilidade
- [x] Mensagem clara quando a permissao nao foi concedida
- [ ] TigerVNC viewer conecta ao servidor rodando num Mac

## Referencias
- Origem: `PLANO.md` (branch `fase-2`, commit 9a0df7e), secao "Progresso consolidado (apos a v0.3)".

## Historico
- 2026-11-26: registrado a partir da analise das fases 0 a 3.
- 2026-11-26: deteccao de permissoes TCC implementada (`macos::permissions()` com `CGPreflightScreenCaptureAccess` e `AXIsProcessTrusted`). Sem Gravacao de Tela, `CgCapture::new` pede a permissao e falha com instrucao; sem Acessibilidade, a injecao falha com instrucao em vez de descartar eventos em silencio. Verificado apenas com clippy para `aarch64-apple-darwin`. **Impossivel neste ambiente:** a migracao para ScreenCaptureKit (`SCStream`, API Objective-C assincrona) e os testes em macOS 14/15 exigem um Mac; escrever o backend SCK sem poder executa-lo seria entregar codigo nao validado, entao fica pendente para quem tiver o hardware.
- 2026-11-26: **Impossibilidade formal registrada.** Os tres criterios abertos (ScreenCaptureKit no macOS 14/15, CGEvent com Acessibilidade e TigerVNC conectando ao servidor num Mac) so podem ser cumpridos executando num Mac. Este ambiente e Windows 11, sem Mac fisico, sem VM macOS (a licenca da Apple so permite macOS virtualizado em hardware Apple) e sem autorizacao para disparar runners `macos-latest` no GitHub (exige push). O item permanece `em-andamento`, bloqueado por hardware, e so pode ser concluido por quem tiver um Mac.
