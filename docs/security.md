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
