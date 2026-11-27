# Servidor central OpenVNC (on-premises)

`openvnc-central` e um servidor da propria empresa que concentra usuarios,
grupos, maquinas e permissoes. Ele nao depende de internet nem de nuvem:
roda numa maquina da rede interna, so fala HTTPS e tem a propria CA.

Fluxo:

1. O usuario entra no central (usuario e senha, ou codigo de dispositivo).
2. O central lista as maquinas liberadas para ele, com as permissoes.
3. Ao escolher uma maquina, o cliente pede um **ticket**: um JWT ES256 de
   vida curta (padrao 120 s) com `iss`, `aud=openvnc`, `sub`,
   `preferred_username`, `groups`, `openvnc_machine`, `openvnc_perms`,
   `exp` e `jti`.
4. O cliente conecta no protocolo nativo e envia o ticket como token OIDC.
5. O servidor da maquina confere a assinatura pelo `/jwks` do central,
   confere que `openvnc_machine` e ele mesmo e aplica as permissoes.

## Instalacao

```toml
# central.toml
listen = "0.0.0.0:8443"
issuer = "https://central.empresa.local:8443"   # URL que clientes e servidores usam
state_dir = "central-state"                      # CA, chave ES256 e store.json
# tls_names = ["central.empresa.local", "10.0.0.2"]  # vazio = host do issuer
# client_id = "openvnc"      # aud dos tickets
# ticket_ttl = 120           # segundos
# session_ttl = 900          # sessao de login, segundos
# audit_log = "audit.log"    # vazio = state_dir/audit.log
# lockout_free = 5           # falhas livres antes do bloqueio progressivo
# max_connections = 256
```

```sh
openvnc-central -c central.toml init                 # CA, chaves e banco vazio
openvnc-central -c central.toml export-ca --out ca.pem
openvnc-central -c central.toml serve
```

Distribua `ca.pem` para clientes e servidores (ou instale no sistema).
Tambem fica disponivel em `GET /ca.pem`, mas so confie nela por um canal
seguro.

## Administracao (CLI)

As senhas vem da variavel `OPENVNC_CENTRAL_PASSWORD` ou de um prompt, nunca
da linha de comando. Senhas sao guardadas com Argon2id.

```sh
openvnc-central -c central.toml group add suporte
openvnc-central -c central.toml user add alice --group suporte
openvnc-central -c central.toml user add root --admin
openvnc-central -c central.toml user passwd|disable|enable|del alice
openvnc-central -c central.toml machine add pc-01 --name "Financeiro" \
    --address 10.0.0.5 --port 5901 --fingerprint AA:BB:...
#   imprime o segredo da maquina (ultima linha): guarde, nao aparece de novo
openvnc-central -c central.toml machine reset-secret pc-01
openvnc-central -c central.toml grant --group suporte --machine pc-01 --perms view,control,files
openvnc-central -c central.toml grant --user carol --machine pc-01 --perms view --ask true
openvnc-central -c central.toml revoke --user carol --machine pc-01
openvnc-central -c central.toml grants
openvnc-central -c central.toml audit --limit 100
```

Permissoes: `view` (obrigatoria para abrir a sessao), `control` (teclado e
mouse), `files` (transferencia de arquivos), `clipboard` (reservada).
`--ask true|false` sobrepoe a aprovacao local de quem esta na maquina.
A `--fingerprint` e a saida de `openvnc-server -c s.toml fingerprint`; o
cliente fixa o TLS por ela.

## Configuracao do servidor da maquina

```toml
oidc_issuer = "https://central.empresa.local:8443"
oidc_client_id = "openvnc"
oidc_ca = "ca.pem"
central_machine_id = "pc-01"      # recusa tickets de outras maquinas e aplica perms
central_url = "https://central.empresa.local:8443"   # opcional: envia auditoria
central_secret_env = "OPENVNC_CENTRAL_SECRET"         # ou central_secret = "..."
```

Com `central_machine_id`, um ticket sem `openvnc_perms` e recusado. Sem
`control`, a entrada e ignorada (evento `input_denied`, uma vez por
sessao); sem `files`, a transferencia e recusada. O evento `session_perms`
registra as permissoes de cada sessao. Com `central_url`, os eventos de
auditoria sao enviados em lotes para `POST /api/audit` (melhor esforco; o
segredo nunca vai para o log).

## Clientes

Desktop: marque **Servidor central da empresa**, informe URL, CA (opcional),
usuario e senha, clique em uma maquina da lista.

CLI:

```sh
OPENVNC_CENTRAL_PASSWORD=... openvnc central-login https://central:8443 --user alice --ca ca.pem
openvnc native pc-01 --central https://central:8443 --central-ca ca.pem --user alice -o tela.png
```

Sem a variavel, a senha e pedida no terminal (`--password-stdin` le uma
linha da entrada padrao).

## API

| Metodo | Caminho | Uso |
|---|---|---|
| GET | `/.well-known/openid-configuration`, `/jwks` | descoberta OIDC e chave ES256 |
| GET | `/ca.pem`, `/health` | CA e saude |
| POST | `/api/login` | `{"user","password"}` devolve `session` |
| GET | `/api/machines` | catalogo (Bearer sessao) |
| POST | `/api/ticket` | `{"machine"}` devolve `ticket` (403 sem concessao) |
| POST | `/api/audit` | ndjson, `Authorization: Machine <id> <segredo>` |
| GET | `/api/audit?limit=N` | auditoria, so administradores |
| POST | `/oauth/device`, `/oauth/token`; GET/POST `/device` | fluxo por codigo de dispositivo |

Falhas de login seguidas geram bloqueio progressivo por usuario e por IP.

## Limitacoes

- Sem pagina web de administracao (so a CLI).
- O servidor da maquina nao guarda `jti` usados: um ticket pode ser
  reaproveitado dentro da validade (curta). Mantenha `ticket_ttl` baixo.
- `clipboard` ainda nao e aplicada (nao ha canal de area de transferencia).
- Sessoes de login ficam em memoria: reiniciar o central encerra todas.

## Teste ponta a ponta

```sh
python -I tests/security/central_e2e.py <dir com openvnc-central, openvnc-server e openvnc>
```
