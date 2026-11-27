# Política de segurança

## Reportando vulnerabilidades
Não abra issue pública. Use **GitHub → Security → Report a vulnerability** (private advisory) neste repositório. Resposta inicial em até 7 dias; divulgação coordenada após correção.

## Modelo de ameaça (resumo)
- Todo dado vindo do par remoto é hostil: parsers com limites, aritmética checada, proteção contra bombas de descompressão, fuzzing contínuo.
- RFB sem TLS **não é seguro** (VNC Auth/DES é fraco, tráfego em claro). O cliente sempre avisa; recomenda-se SSH, VPN ou TLS.
- Certificados inválidos nunca são aceitos silenciosamente; sem downgrade de conexão moderna para insegura.
- Senhas, chaves e conteúdo de tela nunca vão para logs.
- Dependências verificadas por `cargo audit` e `cargo deny` no CI.
- Nenhum serviço externo: o servidor não abre conexões de saída, não tem telemetria nem conta online.
- Força bruta limitada por IP (bloqueio exponencial de 30 s a 15 min).
- Acesso restringível por rede (`allowed_networks`, `lan_only`) e autenticação delegável ao diretório da empresa (`auth_command`).
- Toda conexão, autenticação, recusa, bloqueio e transferência de arquivo vai para o log de auditoria (JSON lines).

Detalhes: [docs/security.md](docs/security.md). Uso corporativo (rede local, LDAP/AD, RADIUS, SSO, auditoria): [docs/enterprise.md](docs/enterprise.md).
