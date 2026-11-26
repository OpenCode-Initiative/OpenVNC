# RFB no OpenVNC

## Handshake por versão
| Etapa | 3.3 | 3.7 | 3.8 |
|---|---|---|---|
| Segurança | servidor escolhe (u32) | lista de tipos, cliente escolhe | igual 3.7 |
| SecurityResult com None | não enviado | não enviado | enviado |
| Motivo de falha | não | não | string |

## Encodings
| Encoding | ID | Prioridade |
|---|---|---|
| Raw | 0 | P0 |
| CopyRect | 1 | P0 |
| Hextile | 5 | P0 |
| ZRLE | 16 | P0 |
| Tight | 7 | P1 |
| Cursor | -239 | P1 |
| DesktopSize | -223 | P1 |
| ExtendedDesktopSize | -308 | P2 |
