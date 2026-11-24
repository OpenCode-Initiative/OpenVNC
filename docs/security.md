# Segurança — controles

| Controle | Requisito |
|---|---|
| Mensagens inválidas | Rejeitar com `Error::Protocol` |
| Payload gigante | Limites configuráveis e obrigatórios |
| Descompressão | Limite de saída |
| Inteiros | `checked_*` em aritmética de tamanho |
| TLS | Validar cadeia e identidade; TOFU explícito |
| Autenticação | Nunca registrar senhas |
| Reconexão | Limite de tentativas e backoff |
| Dependências | `cargo audit`, `cargo deny` |
| Downgrade | Com TLS pedido (`--tls/--pin/--tofu/--ca`), o cliente recusa servidores sem VeNCrypt; `require_tls` no servidor oferece só VeNCrypt |
| Pinning/TOFU | `--pin` fixa o SHA-256 do certificado; `--tofu-accept` grava no known_hosts e depois exige o mesmo certificado |
| Pareamento | Token de 256 bits mostrado uma vez; o servidor guarda só o SHA-256; só trafega dentro do TLS (X509Plain) |
| Revogação | `pair revoke <id>` vale para a próxima conexão |
| Auditoria | JSON lines em `<state_dir>/audit.log`: conexão, TLS, auth (com motivo da falha), recusa, desconexão; nunca tokens nem senhas |
