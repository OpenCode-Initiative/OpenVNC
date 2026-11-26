# RFC 0001: Protocolo nativo OpenVNC (rascunho 0)

Status: rascunho, instavel. Implementacao de referencia: `core/crates/openvnc-protocol`.

## Transporte

Roda sobre TCP+TLS 1.3 ou QUIC (ALPN `openvnc-quic/0`). Sem TLS so em modo de teste explicito.
No QUIC, cada canal logico (controle, entrada, graficos, metadados) e um stream proprio; no TCP,
todas as mensagens compartilham o mesmo stream.

## Quadro

Todos os inteiros sao big-endian.

| Campo   | Tipo | Descricao                                  |
|---------|------|--------------------------------------------|
| Version | u16  | `0` neste rascunho                         |
| Type    | u16  | codigo da mensagem                         |
| Flags   | u16  | reservado, deve ser `0`                    |
| Length  | u32  | tamanho do payload, limite padrao 16 MiB   |

Strings: `u16` de tamanho + UTF-8, no maximo 4096 bytes. Blobs: `u32` de tamanho + bytes.
Booleanos: `u8` 0 ou 1, qualquer outro valor e erro. Bytes sobrando no payload sao erro.

## Mensagens

| Codigo | Nome          | Payload |
|--------|---------------|---------|
| 0x0001 | CLIENT_HELLO  | min_ver u16, max_ver u16, n u16, caps u32[n], nome str |
| 0x0002 | SERVER_HELLO  | ver u16, n u16, caps u32[n], na u8, metodos u8[na], nome str |
| 0x0003 | AUTH_REQUEST  | metodo u8, usuario str, segredo (u16 + bytes) |
| 0x0004 | AUTH_RESULT   | ok bool, motivo str |
| 0x0010 | DISPLAY_INFO  | largura u16, altura u16, nome str |
| 0x0011 | FRAME_UPDATE  | seq u64, n u16, rects[n] = x,y,w,h u16, encoding u16, dados blob |
| 0x0012 | FRAME_ACK     | seq u64 |
| 0x0020 | INPUT_EVENT   | 0: x u16, y u16, botoes u8; 1: keysym u32, down bool |
| 0x0021 | CURSOR_UPDATE | hot_x, hot_y, w, h u16 (max 256), rgba[w*h*4] |
| 0x0030 | CLIPBOARD     | texto blob UTF-8 (max 1 MiB) |
| 0x0040 | FILE_OFFER    | id u32, nome str (sem diretorios), tamanho u64 |
| 0x0041 | FILE_ACCEPT   | id u32, aceito bool |
| 0x0042 | FILE_CHUNK    | id u32, offset u64, dados blob (max 1 MiB) |
| 0x0043 | FILE_END      | id u32, sha256 [32] |
| 0x00F0 | PING          | nonce u64 |
| 0x00F1 | PONG          | nonce u64 |
| 0x00FF | CLOSE         | codigo u16, motivo str |

Encodings de retangulo: 0 RAW (RGBA8), 1 ZLIB (RGBA8 comprimido com zlib), 2 H264
(Annex B, sempre a tela inteira, fluxo continuo por sessao; so com VIDEO_H264).
Capabilities: 0x0001 TILE_RAW, 0x0002 TILE_ZLIB, 0x0010 CURSOR, 0x0020 CLIPBOARD_TEXT,
0x0030 FILE_TRANSFER, 0x0100 VIDEO_H264; 0x0101 reservado para AV1.
Metodos de autenticacao: 0 nenhum, 1 senha, 2 dispositivo pareado.
Codigos de CLOSE: 0 normal, 1 erro de protocolo, 2 falha de autenticacao, 3 versao nao suportada,
4 limite excedido, 5 servidor encerrando.

## Fluxo

1. Cliente envia CLIENT_HELLO. Servidor escolhe a versao comum e a intersecao de capabilities
   e responde SERVER_HELLO (ou CLOSE 3).
2. Cliente envia AUTH_REQUEST com um dos metodos aceitos. Servidor responde AUTH_RESULT; em falha,
   fecha a conexao.
3. Servidor envia DISPLAY_INFO e passa a enviar FRAME_UPDATE. O cliente confirma com FRAME_ACK;
   o servidor mantem no maximo uma janela pequena de quadros sem confirmacao (controle de fluxo).
4. Entrada, clipboard e arquivos fluem em qualquer ordem depois da autenticacao.

## Seguranca

- Limites sao validados antes de qualquer alocacao; erro de decodificacao encerra a conexao.
- Nomes de arquivo com `/`, `\`, `:`, `..` ou caracteres de controle sao recusados.
- Arquivos recebidos so sao gravados depois de aceitos pelo usuario e conferidos pelo SHA-256.
- Segredos de AUTH_REQUEST nunca vao para log.
