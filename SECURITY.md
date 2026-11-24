# Política de segurança

## Reportando vulnerabilidades
Não abra issue pública. Use **GitHub → Security → Report a vulnerability** (private advisory) neste repositório. Resposta inicial em até 7 dias; divulgação coordenada após correção.

## Modelo de ameaça (resumo)
- Todo dado vindo do par remoto é hostil: parsers com limites, aritmética checada, proteção contra bombas de descompressão, fuzzing contínuo.
- RFB sem TLS **não é seguro** (VNC Auth/DES é fraco, tráfego em claro). O cliente sempre avisa; recomenda-se SSH, VPN ou TLS.
- Certificados inválidos nunca são aceitos silenciosamente; sem downgrade de conexão moderna para insegura.
- Senhas, chaves e conteúdo de tela nunca vão para logs.
- Dependências verificadas por `cargo audit` e `cargo deny` no CI.

Detalhes: [docs/security.md](docs/security.md).
