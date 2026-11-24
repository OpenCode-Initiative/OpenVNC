# Protocolos

## RFB legado
Implementação fiel à [RFC 6143](https://www.rfc-editor.org/rfc/rfc6143): versões 3.3, 3.7 e 3.8. Versões desconhecidas são tratadas como 3.3, conforme a RFC. Extensões apenas via encodings/pseudo-encodings registrados na IANA. Ver [docs/protocol-rfb.md](docs/protocol-rfb.md).

## Protocolo nativo OpenVNC (rascunho, não congelado)
- Transporte: QUIC; fallback TCP + TLS 1.3. Endpoint próprio — nunca derivado do banner RFB.
- Header (big-endian): `Version u16 | Type u16 | Flags u16 | Length u32 | Payload`.
- Negociação explícita de capabilities; tamanhos máximos obrigatórios.

| Código | Mensagem | Direção |
|---|---|---|
| 0x0001 | CLIENT_HELLO | C→S |
| 0x0002 | SERVER_HELLO | S→C |
| 0x0003 | AUTH_REQUEST | C→S |
| 0x0004 | AUTH_RESULT | S→C |
| 0x0010 | DISPLAY_INFO | S→C |
| 0x0011 | FRAME_UPDATE | S→C |
| 0x0012 | FRAME_ACK | C→S |
| 0x0020 | INPUT_EVENT | C→S |
| 0x0021 | CURSOR_UPDATE | S→C |
| 0x00FF | CLOSE | ambos |

Mudanças passam por RFC em `docs/RFC/`. Ver [docs/protocol-native.md](docs/protocol-native.md).
