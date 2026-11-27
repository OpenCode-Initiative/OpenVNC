# OpenVNC em empresas: rede local, autenticação central e auditoria

Este guia cobre três perguntas comuns:

1. Dá para rodar só dentro da rede da empresa, sem nada na internet?
2. Dá para autenticar com o diretório da empresa (LDAP/AD, RADIUS, PAM, SSO)?
3. O que fica registrado para auditoria?

Resposta curta para todas: sim. O OpenVNC não depende de nenhum serviço
externo, de nuvem ou do fabricante. Não existe telemetria, conta online
nem servidor de intermediação.

Para gerenciar usuarios, grupos e permissoes por maquina num so lugar,
veja o [servidor central OpenVNC](central.md) (on-premises, sem nuvem).

## 1. Operação 100% local

O servidor só escuta nas portas configuradas (`listen` para RFB, por padrão
5900, e `native_listen` para o protocolo nativo TCP/QUIC). Ele nunca abre
conexões de saída. Para restringir quem pode chegar até ele:

```toml
# config.toml do servidor
listen = "0.0.0.0:5900"
native_listen = "0.0.0.0:5901"

# so aceita estas redes (CIDR, IPv4 e IPv6; IP solto vale como /32 ou /128)
allowed_networks = ["10.0.0.0/8", "192.168.10.0/24", "fd00::/8"]

# alternativa simples: so redes privadas (RFC 1918, link-local, ULA, loopback)
lan_only = true

require_tls = true
max_clients = 2
```

Regras de rede:

- `allowed_networks` tem prioridade. Se preenchida, qualquer IP fora dela é
  recusado antes de qualquer troca de protocolo (evento `rejected`, motivo
  `lan_only`).
- Um IPv4 mapeado em IPv6 (`::ffff:10.1.2.3`) é tratado como o IPv4.
- Para acesso de fora, use a VPN da empresa. Não exponha a porta na internet.
- Complemente com o firewall do sistema: as duas camadas são independentes.

## 2. Autenticação com o diretório da empresa (`auth_command`)

Em vez de embutir clientes LDAP, Kerberos ou SAML no servidor (mais código
de rede exposto, mais dependências), o OpenVNC delega a decisão a um
programa escolhido pela empresa. É o mesmo modelo de `pam_exec`, `checkpassword`
e de vários servidores de e-mail.

```toml
require_tls = true              # obrigatorio: a senha so trafega dentro do TLS
auth_command = ["/usr/local/libexec/openvnc-auth-ldap"]
auth_timeout_secs = 10          # padrao 10
```

Contrato do programa:

| Item | Como funciona |
|---|---|
| Usuário | variável de ambiente `OPENVNC_USER` (sem caracteres de controle, até 256 bytes) |
| Origem | variável de ambiente `OPENVNC_PEER` (`ip:porta` do cliente) |
| Senha | entrada padrão, sem quebra de linha no fim. Nunca vai na linha de comando, então não aparece em `ps` nem no Gerenciador de Tarefas |
| Decisão | código de saída `0` aceita. Qualquer outro código, falha ao iniciar ou estouro do tempo recusa (falha fechada) |
| Tempo | depois de `auth_timeout_secs` o processo é encerrado e o login recusado |
| Saída | stdout é ignorado; stderr vai para o log de diagnóstico (nunca para a auditoria) |

O servidor recusa iniciar com `auth_command` sem `require_tls`.

Como o cliente usa:

- **Cliente desktop:** preencha usuário e senha na tela de conexão. Usuários
  que começam com `dev-` são tratados como dispositivos pareados (token).
- **RFB/VeNCrypt (X509Plain):** qualquer cliente VNC com VeNCrypt envia
  usuário e senha. O usuário reservado `openvnc` continua valendo para a
  senha local do servidor, e IDs de dispositivo pareado continuam valendo
  para tokens.
- **Protocolo nativo:** método `PASSWORD` com usuário preenchido.

### Exemplo: LDAP ou Active Directory

```sh
#!/bin/sh
# /usr/local/libexec/openvnc-auth-ldap
# Aceita se o bind com as credenciais do usuario funcionar e ele estiver no grupo.
set -eu
case "$OPENVNC_USER" in *[!A-Za-z0-9._-]*) exit 1;; esac   # nada de injecao de DN
PASSFILE=$(mktemp); trap 'rm -f "$PASSFILE"' EXIT
cat > "$PASSFILE"
ldapwhoami -x -ZZ -H ldap://dc1.empresa.local \
  -D "$OPENVNC_USER@empresa.local" -y "$PASSFILE" >/dev/null 2>&1 || exit 1
# opcional: exige o grupo "Suporte-Remoto"
ldapsearch -x -ZZ -H ldap://dc1.empresa.local -D "$OPENVNC_USER@empresa.local" -y "$PASSFILE" \
  -b "dc=empresa,dc=local" \
  "(&(sAMAccountName=$OPENVNC_USER)(memberOf=CN=Suporte-Remoto,OU=Grupos,DC=empresa,DC=local))" dn \
  | grep -q '^dn:'
```

Use `-ZZ` (StartTLS obrigatório) ou `ldaps://`. Nunca faça bind em texto claro.

### Exemplo: RADIUS (inclusive com MFA por push/OTP)

```sh
#!/bin/sh
set -eu
PASS=$(cat)
printf 'User-Name = "%s"\nUser-Password = "%s"\n' "$OPENVNC_USER" "$PASS" \
  | radclient -t 8 radius.empresa.local:1812 auth "$(cat /etc/openvnc/radius.secret)" \
  | grep -q 'Access-Accept'
```

Ajuste `auth_timeout_secs` para caber a aprovação do MFA (por exemplo 30).

### Exemplo: PAM (contas do próprio sistema ou SSSD)

Com `pamtester` instalado e um serviço `/etc/pam.d/openvnc`:

```sh
#!/bin/sh
exec pamtester openvnc "$OPENVNC_USER" authenticate
```

(o `pamtester` lê a senha da entrada padrão).

### Windows (Active Directory)

`auth_command` aceita qualquer executável. Exemplo com PowerShell:

```toml
auth_command = ["powershell", "-NoProfile", "-NonInteractive", "-File", "C:\\OpenVNC\\auth-ad.ps1"]
```

```powershell
# auth-ad.ps1
$pw = [Console]::In.ReadToEnd()
Add-Type -AssemblyName System.DirectoryServices.AccountManagement
$ctx = New-Object System.DirectoryServices.AccountManagement.PrincipalContext('Domain', 'empresa.local')
if (-not $ctx.ValidateCredentials($env:OPENVNC_USER, $pw)) { exit 1 }
$u = [System.DirectoryServices.AccountManagement.UserPrincipal]::FindByIdentity($ctx, $env:OPENVNC_USER)
if (-not $u.IsMemberOf($ctx, 'SamAccountName', 'Suporte-Remoto')) { exit 1 }
exit 0
```

### Quem pode acessar qual máquina (controlado pelo AD)

O mesmo script pode decidir por máquina: crie no AD um grupo por computador
(ou por setor) e deixe o script exigir o grupo da máquina em que ele roda.
Assim a permissão é dada e retirada só no AD, sem tocar nos servidores.

```powershell
# auth-ad.ps1, variante por maquina: exige o grupo VNC-<NOME-DO-COMPUTADOR>
# ou o grupo geral VNC-Todos
$pw = [Console]::In.ReadToEnd()
Add-Type -AssemblyName System.DirectoryServices.AccountManagement
$ctx = New-Object System.DirectoryServices.AccountManagement.PrincipalContext('Domain', 'empresa.local')
if (-not $ctx.ValidateCredentials($env:OPENVNC_USER, $pw)) { exit 1 }
$u = [System.DirectoryServices.AccountManagement.UserPrincipal]::FindByIdentity($ctx, $env:OPENVNC_USER)
if ($null -eq $u) { exit 1 }
foreach ($g in @("VNC-$env:COMPUTERNAME", 'VNC-Todos')) {
  if ($u.IsMemberOf($ctx, 'SamAccountName', $g)) { exit 0 }
}
exit 1
```

Com GPO, o mesmo `config.toml` e o mesmo script vão para todas as máquinas.
O nome do usuário do AD fica no log de auditoria (`user_auth`) e aparece no
aviso de aprovação (seção 4).

### SSO (OIDC, SAML, Entra ID, Okta, Keycloak)

#### OIDC nativo por código de dispositivo (recomendado)

O servidor valida diretamente um `id_token` OIDC emitido pelo provedor da
empresa (Entra ID, Okta, Keycloak, Google Workspace, Authentik e afins). O
cliente usa o fluxo de código de dispositivo (RFC 8628): mostra uma URL e um
código curto, o usuário entra no navegador (com MFA e acesso condicional do
provedor) e o cliente recebe o token. Só vale no protocolo nativo
(`native_listen`); clientes RFB comuns continuam com senha ou `auth_command`.

```toml
# config.toml do servidor
require_tls = true                 # obrigatorio com OIDC
native_listen = "0.0.0.0:5901"     # obrigatorio com OIDC
oidc_issuer = "https://login.empresa.local/realms/ti"   # https obrigatorio
oidc_client_id = "openvnc"         # cliente publico com device grant
oidc_scope = "openid profile email"          # padrao
oidc_user_claim = "preferred_username"       # padrao; Entra: "upn" ou "email"
oidc_groups_claim = "groups"                 # padrao; Entra: "groups" ou "roles"
oidc_allowed_groups = ["suporte"]            # vazio = qualquer usuario do provedor
# oidc_ca = "C:/OpenVNC/ca-interna.pem"      # CA extra para o provedor (opcional)
```

O que o servidor verifica em cada token: assinatura RS256 ou ES256 pela JWKS
do provedor (descoberta em `/.well-known/openid-configuration`, recarregada no
máximo uma vez por minuto quando aparece um `kid` novo), `iss` igual ao
configurado, `aud` contendo o `client_id` (e `azp`, se houver), `exp`, `nbf`
e `iat` com 60 s de tolerância, o grupo exigido e o usuário. Um token só pode
ser usado uma vez (proteção contra repetição até o `exp`). Só HTTPS é aceito
para o provedor (HTTP apenas em loopback, para testes), sem seguir
redirecionamentos.

No provedor: crie um cliente **público** com o *OAuth 2.0 Device
Authorization Grant* ativo e um mapeador que coloque os grupos no `id_token`.
No Entra ID, ative "Allow public client flows" no registro do aplicativo e
configure "groups claim" (ou use app roles com `oidc_groups_claim = "roles"`).
No Okta, crie um app "Native" com o grant "Device Authorization". No
Keycloak, ative "OAuth 2.0 Device Authorization Grant" no cliente e adicione
o mapeador "Group Membership" (sem caminho completo).

No cliente:

```sh
openvnc-cli native servidor:5901 --sso              # mostra URL e codigo
openvnc-cli native servidor:5901 --sso --sso-ca ca-interna.pem
```

No cliente desktop: em **Opções avançadas**, marque **Entrar com a conta da
empresa (SSO)** (exige uma opção de segurança TLS). Se o provedor usa CA
interna, informe o PEM em **CA do provedor SSO**. Ao conectar, a janela mostra
o endereço e o código; depois da aprovação no navegador a sessão abre numa aba,
pelo protocolo nativo (porta de arquivos, padrão porta VNC + 1). O botão
**Cancelar** interrompe a espera.

Auditoria: `oidc_auth` (peer, usuário) no sucesso e `oidc_auth_failed`
(peer, motivo) na recusa; o token nunca é gravado.

#### Pontes para SAML e provedores sem device grant

Para SSO por SAML ou provedores sem o fluxo de dispositivo, dois caminhos
funcionam com `auth_command`:

1. **Senha de uso único emitida pelo portal SSO.** O usuário entra no portal
   da empresa (autenticado por SSO), recebe um código curto e válido por
   poucos minutos e digita esse código como senha no OpenVNC. O
   `auth_command` consulta o portal (`curl` para uma API interna) para validar
   o par usuário/código. Assim o SSO, o MFA e as políticas de acesso
   condicional continuam no provedor de identidade.
2. **Provedor com interface LDAP ou RADIUS.** Entra ID Domain Services,
   Okta LDAP Interface, Keycloak com federação LDAP, JumpCloud e afins
   expõem LDAP ou RADIUS. Use os exemplos acima.

Validação do código no portal (esqueleto):

```sh
#!/bin/sh
set -eu
CODE=$(cat)
curl -fsS --max-time 8 --cacert /etc/openvnc/portal-ca.pem \
  -H "Authorization: Bearer $(cat /etc/openvnc/portal.token)" \
  --data-urlencode "user=$OPENVNC_USER" --data-urlencode "code=$CODE" \
  --data-urlencode "peer=$OPENVNC_PEER" \
  https://acesso.empresa.local/api/openvnc/verify >/dev/null
```

### Kerberos

O RFB não transporta tíquetes Kerberos/GSSAPI, então o login sem digitar
senha (tíquete da sessão do Windows) não é suportado. O que funciona é validar
usuário e senha contra o KDC pelo `auth_command`:

```sh
#!/bin/sh
# /usr/local/libexec/openvnc-auth-krb5
set -eu
case "$OPENVNC_USER" in *[!A-Za-z0-9._-]*|"") exit 1;; esac
export KRB5CCNAME="MEMORY:openvnc-$$"
# kinit (MIT) le a senha do stdin; o cache em memoria some quando o processo sai
kinit "$OPENVNC_USER@EMPRESA.LOCAL" >/dev/null 2>&1
```

Testado contra um KDC MIT (Debian, krb5 1.21): senha certa aceita; senha
errada, usuário inexistente e usuário com `;` recusados. No Heimdal (macOS,
FreeBSD) troque a linha por `kinit --password-file=STDIN ...`. No Windows, o exemplo de
Active Directory acima já autentica via Kerberos do domínio.

### Boas práticas para o programa de autenticação

- Rode o servidor com uma conta de serviço sem privilégios; o programa herda
  essa conta.
- Valide `OPENVNC_USER` contra uma lista de caracteres permitidos antes de
  montar filtros LDAP, DNs ou comandos.
- Nunca escreva a senha em log, arquivo permanente ou argumento de comando.
- Proteja arquivos de segredo (`radius.secret`, tokens) com permissão 0600.
- Teste a recusa: senha errada, usuário fora do grupo, diretório fora do ar.

## 3. Proteção contra força bruta

Em qualquer método (senha local, token, `auth_command`) e nos dois
protocolos:

- depois de 5 falhas seguidas do mesmo IP, ele é bloqueado por 30 segundos;
- cada nova falha dobra o bloqueio, até 15 minutos;
- enquanto bloqueado, a conexão é recusada logo no aceite (evento
  `rejected`, motivo `lockout`), sem chegar a testar a senha;
- um login aceito zera o contador; falhas antigas (mais de 1 hora) são esquecidas;
- a tabela é limitada (10 mil IPs) para não virar vetor de exaustão de memória.

O `auth_command` ainda deve ter sua própria política de bloqueio de conta no
diretório (o padrão do AD já faz isso).

## 4. Aprovação de quem está na máquina

`ask_before_accept = true` (padrão na instalação Windows) mostra um aviso no
computador acessado e só libera a sessão se alguém aceitar. Útil para
suporte técnico com o usuário presente. No Windows o aviso sai pela bandeja;
no macOS por um diálogo do sistema (`osascript`); no Linux pelo `zenity` ou
`kdialog`. Em todos, se ninguém responder dentro do prazo, a conexão é
recusada (falha fechada). `allow_attended` define o que fazer
quando não há ninguém para aprovar.

A aprovação acontece depois da autenticação, então o aviso mostra quem está
pedindo: `joao.silva de 10.1.2.3:51234` para contas do diretório
(`auth_command`) ou o nome do dispositivo pareado; com a senha única do
servidor, só o endereço. O aviso espera 30 s; os clientes OpenVNC aguardam
45 s pela resposta, então uma única aprovação basta (não há novos pedidos
repetidos enquanto o usuário decide).

## 5. Log de auditoria

Arquivo `audit.log` no diretório de estado (ou `audit_log` na configuração),
uma linha JSON por evento, com `ts` em segundos Unix (UTC). Exemplo: `{"ts":1764115200,"event":"auth_failed","peer":"10.1.2.3:51234","reason":"senha incorreta"}`. Senhas, tokens e conteúdo
de tela nunca são gravados.

| Evento | Quando | Campos principais |
|---|---|---|
| `server_start` | servidor iniciado | `listen`, `tls` (`required`, `offered`, `off`) |
| `connect` | conexão TCP aceita | `peer` |
| `rejected` | conexão recusada antes da autenticação | `peer`, `reason` (`lan_only`, `max_clients`, `lockout`, `local_user`) |
| `tls` | handshake TLS concluído | `peer`, `subtype` |
| `auth_ok` | autenticação aceita (nativo) | `peer`, `user` |
| `auth_failed` | autenticação recusada | `peer`, `reason` |
| `password_auth` / `password_auth_failed` | senha local (usuário `openvnc`) aceita ou recusada | `peer`, `user` |
| `user_auth` | `auth_command` aceitou | `peer`, `user` |
| `user_auth_failed` | `auth_command` recusou | `peer`, `user`, `reason` |
| `device_auth` / `device_auth_failed` | token de dispositivo pareado aceito ou recusado | `peer`, `device` |
| `oidc_auth` / `oidc_auth_failed` | SSO OIDC aceito ou recusado (token nunca registrado) | `peer`, `user` ou `reason` |
| `lockout` | IP passou a ficar bloqueado | `peer`, `secs` |
| `session` | sessão iniciada | `peer`, `encryption` |
| `device_paired` / `device_revoked` | pareamento criado ou revogado | `device` |
| `file_received` / `file_offered` | transferência de arquivo | `peer`, nome, tamanho |
| `protocol_error` | cliente enviou dados inválidos ou abandonou o handshake | `peer`, `error` |
| `disconnect` | fim da sessão | `peer` |

Para centralizar: envie o arquivo ao SIEM (Splunk, Elastic, Graylog, Wazuh,
Sentinel) com o agente de coleta de arquivos de cada um (Filebeat,
Fluent Bit, NXLog, Wazuh agent). Cada linha já é um JSON completo.
Recomendações:

- proteja o arquivo contra escrita pelo usuário comum (só a conta de serviço);
- faça rotação com `logrotate` ou equivalente (modo `copytruncate`);
- crie alertas para `lockout`, rajadas de `auth_failed` e `rejected` com
  motivo `lan_only` (alguém de fora tentando).

## 6. Lista de verificação para produção

- [ ] `require_tls = true` e certificado da CA interna (`tls_cert`, `tls_key`); clientes com `--ca` ou `--pin`
- [ ] `allowed_networks` com as redes internas (ou `lan_only = true`)
- [ ] `auth_command` integrado ao diretório, testado com recusa
- [ ] `ask_before_accept` conforme a política de privacidade
- [ ] `audit.log` coletado pelo SIEM, com alertas
- [ ] firewall do sistema liberando as portas só para as redes internas
- [ ] serviço rodando com conta sem privilégios administrativos
- [ ] `files_send` / `files_receive` desligados se a transferência de arquivos não for permitida
- [ ] prefira `password_hash` ou `auth_command` a uma senha local usada só pelo VNC Auth (veja abaixo)
- [ ] bateria de segurança (`tests/security/battery.py`) rodada contra o binário que vai para produção

### Limite do VNC Auth

O VNC Auth clássico (DES, subtipo VeNCrypt 261) usa só os **8 primeiros
caracteres** da senha. É uma limitação do protocolo. Com `require_tls` ele corre
dentro do TLS, mas a força da senha fica limitada a 8 caracteres. Clientes que
mandam usuário e senha (Plain, subtipo 262, usado pelos clientes OpenVNC)
verificam a senha inteira contra `password_hash`, tokens de pareamento ou
`auth_command`.

## 7. Testes de segurança

`tests/security/battery.py` sobe servidores temporários em `127.0.0.1`
(portas 5981 a 5985) e verifica, ao vivo: TLS obrigatório sem tipos em claro,
senha certa/errada/vazia, usuário desconhecido, entrada malformada, bloqueio
por força bruta, auditoria sem a senha, `allowed_networks`, `auth_command`
(aceite, recusa, caractere de controle, tempo esgotado com falha fechada) e
recusa de iniciar `auth_command` sem TLS.

```sh
python -I tests/security/battery.py caminho/para/openvnc-server [pasta-temporaria]
```

A senha de teste é aleatória e só passa por variável de ambiente.

`tests/security/sso_e2e.py` testa o SSO de ponta a ponta com um Keycloak
temporário no Podman: gera CA e certificados, cria o realm, o cliente com
device grant, grupos e usuários com senhas aleatórias, aprova o login como o
navegador faria e verifica: conexão aceita, login negado no provedor,
restrição por `oidc_allowed_groups`, auditoria `oidc_auth`/`oidc_auth_failed`
sem token nem senha e recusa de iniciar OIDC sem TLS. No fim apaga o
container, a imagem e os arquivos gerados.

```sh
python -I tests/security/sso_e2e.py pasta/com/openvnc-server-e-openvnc
```

Requer `podman` e `openssl` no PATH e a porta 8443 livre.
