# Debitos tecnicos

Registro unico de debitos tecnicos, lacunas de teste, funcionalidades pendentes e bugs conhecidos do OpenVNC. O `PLANO.md` diz o que fazer em cada fase; esta pasta diz o que ficou devendo.

## Estrutura

```
docs/technical_debits/
  README.md                  este arquivo: padrao e indice
  _TEMPLATE.md               modelo para novos itens
  <componente>/TD-NNN-<slug>.md
```

Componentes: `servidor`, `plataforma` (captura e entrada por SO), `cliente` (desktop, CLI, codecs do cliente), `transporte`, `protocolo` (protocolo nativo e FFI), `ci`, `interop`.

## Regras

1. **Um arquivo por item.** Nome `TD-NNN-<slug>.md`, com `NNN` sequencial global (nunca reutilizado) e slug em kebab-case sem acentos.
2. **Copie o `_TEMPLATE.md`** e preencha todo o cabecalho YAML.
3. **Campos:**
   - `tipo`: `divida-tecnica` (solucao provisoria que precisa ser refeita), `lacuna-de-teste` (existe, mas sem evidencia de funcionar), `funcionalidade-pendente` (planejada e nao feita), `bug-conhecido`.
   - `prioridade`: `P0` bloqueia release ou aceite; `P1` afeta uso real ou seguranca; `P2` desempenho ou manutencao; `P3` melhoria.
   - `status`: `aberto`, `em-andamento`, `resolvido`, `descartado`.
4. **Criterio de conclusao verificavel.** Cada item tem checkboxes objetivos. So marque `resolvido` com todos marcados e com a evidencia (commit, PR, job de CI ou medicao) no Historico.
5. **Nao apague itens resolvidos.** Mude o status, atualize `atualizado-em` e registre no Historico. `descartado` exige o motivo.
6. **Mantenha o indice abaixo** em sincronia ao criar ou mudar o status de um item.
7. Ao encerrar uma fase, todo "fica para depois" ou "com ressalvas" do `PLANO.md` vira um item aqui.

## Indice

| ID | Titulo | Componente | Tipo | Prioridade | Status | Fase-alvo |
|---|---|---|---|---|---|---|
| [TD-001](ci/TD-001-jobs-interop-nunca-rodaram-no-github.md) | Jobs de interop nunca rodaram no GitHub Actions | ci | lacuna-de-teste | P0 | aberto | v0.3 |
| [TD-002](plataforma/TD-002-macos-screencapturekit.md) | macOS usa CGDisplayCreateImage obsoleto e nunca rodou num Mac | plataforma | divida-tecnica | P1 | em-andamento | v0.4 |
| [TD-003](plataforma/TD-003-wayland-portal-quadros-reais.md) | Wayland: portal com quadros reais e entrada RemoteDesktop nao testados | plataforma | lacuna-de-teste | P1 | aberto | v0.4 |
| [TD-006](cliente/TD-006-desktop-ui-tls.md) | Cliente desktop sem UI para TLS (pin, TOFU, usuario/dispositivo) | cliente | funcionalidade-pendente | P1 | resolvido | v0.4 |
| [TD-010](protocolo/TD-010-protocolo-nativo-e-ffi-esqueletos.md) | openvnc-protocol e openvnc-ffi sao esqueletos vazios | protocolo | funcionalidade-pendente | P1 | resolvido | v0.4 |
| [TD-004](plataforma/TD-004-x11-mit-shm-damage.md) | X11 captura o quadro inteiro com GetImage | plataforma | divida-tecnica | P2 | resolvido | v0.4 |
| [TD-011](protocolo/TD-011-video-h264-av1.md) | Protocolo nativo sem codec de video para regioes de movimento | protocolo | funcionalidade-pendente | P2 | resolvido | v0.4 |
| [TD-005](transporte/TD-005-quic-nao-integrado.md) | QUIC nao esta ligado ao servidor nem ao cliente e nao foi medido em rede real | transporte | funcionalidade-pendente | P2 | resolvido | v0.4 |
| [TD-008](cliente/TD-008-renderer-proprio-backends.md) | Renderer proprio sem backends nativos por SO | cliente | divida-tecnica | P2 | resolvido | v0.4 |
| [TD-007](cliente/TD-007-tight-jpeg.md) | Tight sem JPEG no cliente | cliente | funcionalidade-pendente | P3 | resolvido | v0.4 |
| [TD-009](interop/TD-009-tightvnc-imagem-preta.md) | TightVNC 2.x no Windows entrega imagem preta | interop | bug-conhecido | P3 | aberto | v1.0 |

Indice ordenado por prioridade. Proximo ID livre: **TD-012**.
