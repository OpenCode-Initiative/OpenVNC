# Segurança: controles

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
| Força bruta | 5 falhas seguidas por IP bloqueiam por 30 s, dobrando até 15 min; recusa já no aceite (`rejected`/`lockout`); sucesso zera; tabela limitada a 10 mil IPs |
| Restrição de rede | `allowed_networks` (CIDR, IPv4/IPv6) ou `lan_only`; checado antes de qualquer byte de protocolo |
| Autenticação externa | `auth_command` (LDAP/AD, RADIUS, PAM, ponte SSO): senha só pelo stdin, tempo limite, falha fechada, exige `require_tls` |
| Aprovação local | `ask_before_accept` pede confirmação de quem está na máquina |
| Transferência de arquivos | `files_send`/`files_receive` desligáveis, limite `files_max_mb`, diretório fixo, auditada |
| Explorador de arquivos | Caminhos absolutos, sem `..`, NUL, controle, UNC ou prefixo de dispositivo; canonicalizados e confinados a `files_root` (quando definido); links simbólicos nunca seguidos na escrita e na exclusão; listar e baixar exigem `files_send`, criar, renomear, enviar e apagar exigem `files_receive`; cada operação auditada (`fs_list`, `fs_download`, `fs_upload`, `fs_mkdir`, `fs_rename`, `fs_delete`) |
| Bloqueio de entrada local | Só com permissão de controle (sessão sem `view_only`); ganchos de baixo nível que descartam só eventos físicos; liberado ao fim da sessão, na queda da conexão, após 10 s sem tráfego e por guarda `Drop`; auditado (`input_lock`/`input_unlock`) |
| Segredos em repouso | senha local guardada como hash (`password_hash`) ou protegida por DPAPI no Windows (`password_protected`); tokens de pareamento só como SHA-256 |

## Acessos: quem pode entrar e como

1. **Rede:** o IP passa por `allowed_networks`/`lan_only` e pelo bloqueio de força bruta.
2. **Limite:** no máximo `max_clients` sessões simultâneas.
3. **TLS:** com `require_tls`, só VeNCrypt (RFB) ou TLS/QUIC (nativo); sem downgrade.
4. **Credencial** (uma das):
   - senha local do servidor (usuário `openvnc`);
   - token de dispositivo pareado (`pair add`, revogável com `pair revoke`);
   - usuário e senha da empresa via `auth_command`;
   - SSO OIDC (`id_token` por código de dispositivo, só no protocolo nativo, exige TLS).
5. **Aprovação:** `ask_before_accept` (quando ativo).
6. **Permissões da sessão:** `view_only`, `files_send`, `files_receive`.

Sem nenhuma credencial configurada o servidor só aceita escutar em loopback (`allow_no_auth`).

## Explorador de arquivos

No cliente desktop, o botão **Explorador** abre dois painéis: este computador à esquerda e o computador remoto à direita. Cada painel tem barra de caminho, subir um nível, atualizar, lista de unidades e ordenação por nome, tamanho ou data. Arraste itens de um painel para o outro, ou use **Enviar**/**Baixar**; pastas vão inteiras (recursivo). A fila mostra progresso e permite cancelar; o arquivo parcial é apagado. Se o destino já existir, o cliente pede confirmação antes de substituir. **Nova pasta**, **Renomear** e **Apagar** (com confirmação) funcionam nos dois lados. No celular aparece um painel por vez, com seletor "Este aparelho"/"Remoto".

No servidor:

- `files_send = false` desliga listar e baixar; `files_receive = false` desliga criar, renomear, enviar e apagar. Sem nenhum dos dois o recurso nem é oferecido.
- `files_root = "C:\Compartilhado"` restringe o explorador a uma pasta. Se a pasta não existir, o explorador fica desligado (falha fechada). Sem `files_root`, todas as unidades do usuário do serviço ficam acessíveis.
- `files_max_mb` também limita cada arquivo enviado.
- A raiz nunca pode ser apagada; uma pasta não pode ser movida para dentro dela mesma.

## Bloquear mouse e teclado do computador remoto

A opção **Bloquear mouse e teclado do computador remoto** (barra do cliente, ou menu "..." no celular) impede que alguém na máquina remota use o mouse e o teclado físicos enquanto você controla. A máquina remota mostra um aviso no topo da tela.

- Exige permissão de controle; sessões `view_only` recebem recusa.
- Windows: ganchos `WH_KEYBOARD_LL`/`WH_MOUSE_LL` que descartam eventos não injetados. Não usa `BlockInput`.
- **Ctrl+Alt+Del sempre funciona** (o Windows não deixa bloquear essa sequência), então quem está na máquina sempre consegue recuperá-la.
- Liberação automática: ao desmarcar, ao encerrar a sessão, na queda da conexão, após 10 s sem tráfego do cliente (o cliente envia um ping a cada 3 s enquanto bloqueado) e quando o processo do servidor termina.
- Só funciona quando o servidor roda na sessão do usuário (bandeja). Como serviço na sessão 0 os ganchos não alcançam a área de trabalho do usuário.
- Linux e macOS: responde "não suportado".

## Eventos de auditoria

Lista completa e integração com SIEM em [enterprise.md](enterprise.md#5-log-de-auditoria).

## Limitações conhecidas

- VNC Auth (DES) considera só os 8 primeiros caracteres da senha, usa chave de 56 bits e não cifra o tráfego. Mantenha desligada (é o padrão onde há opção de configuração) e use `password_hash` ou `auth_command`; ligue só para clientes VNC legados, em rede confiável.
- SSO OIDC só no protocolo nativo; sem tíquete Kerberos/GSSAPI nem SAML direto; ver as pontes em [enterprise.md](enterprise.md#sso-oidc-saml-entra-id-okta-keycloak).

## SSO OIDC: reuso de token entre hosts

- **Modo servidor central** (`machine` definido): o ticket traz `openvnc_machine` e `jti`; o host recusa ticket de outra máquina, ticket sem `jti` e reuso do mesmo `iss` + `jti` dentro da validade.
- **Modo SSO genérico** (IdP como Entra ID, Okta, Keycloak, sem `machine`): o ID token só é amarrado à audiência (`aud`, o client id). **Todo host que aceita a mesma audiência aceita o mesmo token.** Um host comprometido (ou um operador mal-intencionado em um deles) que receba o token pode reapresentá-lo em outro host dentro da validade. O cache de reuso é por host e não impede isso.
- Mitigação: defina `OPENVNC_OIDC_HOST_ID=<id do host>` no ambiente do servidor (ou `Verifier::require_host_binding` no código). O token passa a precisar de `openvnc_machine` igual ao id ou de `aud` contendo `<id>` ou `<client_id>:<id>`; configure o IdP para emitir esse claim/audiência por máquina. Sem isso o servidor registra um aviso na inicialização e mantém o comportamento antigo (compatibilidade).
- Alternativa: um client id (audiência) diferente por host ou por grupo de hosts de mesmo nível de confiança, e validade curta do token.
- O cache de reuso usa `iss` + `jti` quando há `jti`; sem `jti`, o hash de `cabeçalho.payload` (a assinatura fica de fora porque ES256 é maleável: `(r, s)` e `(r, n - s)` são ambas válidas).

## Testes de segurança

Bateria ao vivo em `tests/security/battery.py` e SSO ponta a ponta (Keycloak no Podman) em `tests/security/sso_e2e.py` (detalhes em [enterprise.md](enterprise.md#7-testes-de-segurança)).

## Implantação local e corporativa

Ver [enterprise.md](enterprise.md): operação sem internet, LDAP/AD, RADIUS, PAM, SSO e lista de verificação de produção.

Servidor central on-premises (usuarios, grupos, permissoes por maquina e tickets curtos): ver [central.md](central.md).
