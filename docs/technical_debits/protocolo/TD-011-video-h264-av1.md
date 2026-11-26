---
id: TD-011
titulo: Protocolo nativo sem codec de video para regioes de movimento
componente: protocolo
tipo: funcionalidade-pendente
prioridade: P2
status: resolvido
fase-alvo: v0.4
criado-em: 2026-11-26
atualizado-em: 2026-11-26
---

# TD-011: Protocolo nativo sem codec de video para regioes de movimento

## Contexto
O protocolo nativo envia apenas tiles RAW e ZLIB. A Fase 4 preve H.264 (depois AV1) para areas com movimento, mantendo tiles lossless para texto.

## Impacto
Video e animacoes consomem muita banda; tiles ZLIB nao comprimem bem conteudo natural.

## Onde
- `servers/reference/src/native.rs` (`encode_rect`)
- `core/crates/openvnc-client/src/native.rs` (`apply`)
- `core/crates/openvnc-protocol/src/lib.rs` (`encoding`, `capability`)

## Proposta de solucao
1. Escolher biblioteca (openh264 com licenca Cisco, ou encoder do SO: Media Foundation, VideoToolbox, VA-API).
2. Nova capability e encoding, detector de regioes de movimento a partir dos tiles sujos.
3. Medir banda e latencia contra ZLIB.

## Criterio de conclusao
- [x] Encoding de video negociado por capability (`VIDEO_H264`, `encoding::H264 = 2`)
- [x] Servidor e cliente com encode/decode testados (`video::tests`, `native::tests::video_so_com_mudanca_grande`)
- [x] Medicao de banda documentada (abaixo)

## Solucao adotada
- `openvnc-codecs::video` (feature `h264`): `H264Encoder`/`H264Decoder` sobre RGBA, usando o crate `openh264` 0.6, que compila o fonte BSD-2 da Cisco (sem binario pre-compilado e, portanto, sem a cobertura de patentes do binario da Cisco; ver nota).
- Servidor: quando o cliente anuncia `VIDEO_H264` e mais de 25% da tela muda, envia um quadro H.264 de tela inteira com encoder persistente por sessao. Apos 300 ms sem mudancas, reenvia a tela em tiles sem perdas (texto volta nitido).
- Cliente: decoder com estado, recriado a cada `DISPLAY_INFO`. Build sem a feature recusa o encoding e nao anuncia a capability.
- AV1 continua reservado (`0x0101`); fica para quando houver encoder de tempo real viavel em Rust.

## Medicao
`cargo test --release -p openvnc-codecs --features h264 medir_banda -- --ignored --nocapture`, cena sintetica 640x480 com movimento continuo, 60 quadros, 8 Mbit/s:
h264 1865 KiB contra zlib 25231 KiB (13,5x menos banda). Medido em Windows 11, 2026-11-26.

## Nota de licenca
Distribuir H.264 compilado do fonte pode exigir licenca de patentes MPEG LA em alguns paises. A feature pode ser desligada (`--no-default-features`) em builds de distribuicao.

## Referencias
- Origem: `PLANO.md`, Fase 4 item 3.

## Historico
- 2026-11-26: registrado ao concluir os itens 1, 2 e 4 da Fase 4.
- 2026-11-26: resolvido com H.264 via openh264; AV1 segue reservado.
