"""SSO OIDC ponta a ponta: Keycloak (Podman) + openvnc-server + CLI --sso.

Uso: python -I tests/security/sso_e2e.py <dir com openvnc-server e openvnc>

Requer podman e openssl no PATH. Tudo (CA, chaves, senhas aleatorias) e
gerado num diretorio temporario e apagado ao final, junto com o container
e a imagem. Nenhum segredo fica no repositorio.
"""
import html, http.cookiejar, json, os, re, secrets, shutil, ssl, subprocess, sys, tempfile, time, pathlib
import urllib.parse, urllib.request

EXT = ".exe" if os.name == "nt" else ""
T = pathlib.Path(sys.argv[1]).resolve()
SRV, CLI = T / f"openvnc-server{EXT}", T / f"openvnc{EXT}"
D = pathlib.Path(tempfile.mkdtemp(prefix="ovnc-sso-"))
B = "https://localhost:8443"
NAME, IMAGE = "ovnc-sso-e2e", "openvnc-sso-e2e"
ENV = dict(os.environ, MSYS_NO_PATHCONV="1")
RES = []


def check(n, ok, info=""):
    RES.append(ok)
    print(("PASS " if ok else "FAIL ") + n + (f"  ({info})" if info else ""), flush=True)


def sh(*a, **k):
    return subprocess.run(list(a), check=True, capture_output=True, cwd=D, env=ENV, **k)


def certs():
    sh("openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes",
       "-days", "1", "-subj", "/CN=Teste CA", "-addext", "basicConstraints=critical,CA:TRUE",
       "-addext", "keyUsage=keyCertSign", "-keyout", "ca.key", "-out", "ca.pem")
    sh("openssl", "req", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes",
       "-subj", "/CN=localhost", "-keyout", "kc.key", "-out", "kc.csr")
    (D / "ext").write_text("subjectAltName=DNS:localhost,IP:127.0.0.1\nbasicConstraints=CA:FALSE\n"
                           "extendedKeyUsage=serverAuth\n")
    sh("openssl", "x509", "-req", "-in", "kc.csr", "-CA", "ca.pem", "-CAkey", "ca.key",
       "-CAcreateserial", "-days", "1", "-extfile", "ext", "-out", "kc.pem")
    os.chmod(D / "kc.key", 0o644)
    (D / "Containerfile").write_text(
        "FROM quay.io/keycloak/keycloak:26.0\nCOPY kc.pem kc.key /opt/keycloak/conf/\n")


def keycloak(admin_pw):
    sh("podman", "build", "-q", "-t", IMAGE, ".")
    sh("podman", "run", "-d", "--name", NAME, "-p", "127.0.0.1:8443:8443",
       "-e", "KC_BOOTSTRAP_ADMIN_USERNAME=admin", "-e", f"KC_BOOTSTRAP_ADMIN_PASSWORD={admin_pw}",
       IMAGE, "start-dev", "--https-port=8443", "--http-enabled=false",
       "--https-certificate-file=/opt/keycloak/conf/kc.pem",
       "--https-certificate-key-file=/opt/keycloak/conf/kc.key", f"--hostname={B}")
    for _ in range(100):
        try:
            urllib.request.urlopen(B + "/realms/master", context=CTX, timeout=3)
            return
        except Exception:
            time.sleep(3)
    raise RuntimeError("Keycloak nao subiu")


def req(m, path, body=None, tok=None, form=False):
    h, data = {}, None
    if tok:
        h["Authorization"] = "Bearer " + tok
    if body is not None:
        if form:
            data, h["Content-Type"] = urllib.parse.urlencode(body).encode(), "application/x-www-form-urlencoded"
        else:
            data, h["Content-Type"] = json.dumps(body).encode(), "application/json"
    t = urllib.request.urlopen(urllib.request.Request(B + path, data, h, method=m), context=CTX).read()
    return json.loads(t) if t else None


def realm(admin_pw):
    """Realm 'ti', cliente publico com device grant, grupos e dois usuarios."""
    tok = req("POST", "/realms/master/protocol/openid-connect/token",
              {"grant_type": "password", "client_id": "admin-cli", "username": "admin",
               "password": admin_pw}, form=True)["access_token"]
    req("POST", "/admin/realms", {"realm": "ti", "enabled": True}, tok)
    req("POST", "/admin/realms/ti/clients", {
        "clientId": "openvnc", "publicClient": True, "standardFlowEnabled": False,
        "attributes": {"oauth2.device.authorization.grant.enabled": "true"},
        "protocolMappers": [{"name": "groups", "protocol": "openid-connect",
                             "protocolMapper": "oidc-group-membership-mapper",
                             "config": {"claim.name": "groups", "full.path": "false",
                                        "id.token.claim": "true", "access.token.claim": "true"}}]}, tok)
    for g in ("suporte", "vendas"):
        req("POST", "/admin/realms/ti/groups", {"name": g}, tok)
    groups = {g["name"]: g["id"] for g in req("GET", "/admin/realms/ti/groups", tok=tok)}
    pw = {}
    for u, g in (("alice", "suporte"), ("bob", "vendas")):
        pw[u] = secrets.token_urlsafe(12)
        req("POST", "/admin/realms/ti/users", {
            "username": u, "enabled": True, "email": u + "@empresa.test", "emailVerified": True,
            "firstName": u, "lastName": "Teste",
            "credentials": [{"type": "password", "value": pw[u], "temporary": False}]}, tok)
        uid = req("GET", "/admin/realms/ti/users?exact=true&username=" + u, tok=tok)[0]["id"]
        req("PUT", f"/admin/realms/ti/users/{uid}/groups/{groups[g]}", {}, tok)
    return pw


def approve(url, user, pw, accept=True):
    """Faz no Keycloak o que o usuario faria no navegador."""
    op = urllib.request.build_opener(urllib.request.HTTPSHandler(context=CTX),
                                     urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
    page = op.open(url).read().decode()
    for _ in range(4):
        m = re.search(r'<form[^>]*action="([^"]+)"', page)
        if not m:
            break
        act = urllib.parse.urljoin(B + "/", html.unescape(m.group(1)))
        if 'name="username"' in page:
            data = {"username": user, "password": pw}
        elif 'name="accept"' in page or 'name="cancel"' in page:
            data = {"accept": "Yes"} if accept else {"cancel": "No"}
        else:
            break
        page = op.open(act, urllib.parse.urlencode(data).encode()).read().decode()


def server(name, extra):
    d = D / name
    d.mkdir()
    cfg = d / "s.toml"
    cfg.write_text(
        f'listen = "127.0.0.1:5990"\nnative_listen = "127.0.0.1:5991"\ncapture = "test-pattern"\n'
        f'setup_done = true\nrequire_tls = true\ntls_names = ["localhost"]\nask_before_accept = false\n'
        f'audit_log = "{(d / "audit.log").as_posix()}"\nstate_dir = "{d.as_posix()}"\n'
        f'oidc_issuer = "{B}/realms/ti"\noidc_client_id = "openvnc"\n'
        f'oidc_ca = "{(D / "ca.pem").as_posix()}"\n' + extra)
    fp = subprocess.run([str(SRV), "-c", str(cfg), "fingerprint"], capture_output=True, text=True).stdout.strip()
    log = open(d / "srv.log", "w")
    p = subprocess.Popen([str(SRV), "-c", str(cfg)], stdout=log, stderr=log)
    time.sleep(3)
    return p, d, fp


def login(fp, user, pw, accept=True, tag="x"):
    out = D / f"shot-{tag}.png"
    c = subprocess.Popen([str(CLI), "native", "127.0.0.1:5991", "--pin", fp, "--transport", "tcp", "--sso",
                          "--sso-ca", str(D / "ca.pem"), "-o", str(out), "--timeout", "60"],
                         stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    url = None
    for line in c.stderr:
        m = re.search(r"abra (https://\S+)", line)
        if m:
            url = m.group(1)
            break
    if url:
        approve(url, user, pw, accept)
    o, e = c.communicate(timeout=90)
    return c.returncode, o + e, out.exists()


def stop(p):
    p.terminate()
    p.wait(10)


def tests(pw):
    p, d, fp = server("sso", "")
    try:
        rc, out, shot = login(fp, "alice", pw["alice"], tag="alice")
        check("SSO: alice aprova no navegador e conecta", rc == 0 and shot, out.strip()[-200:])
        rc, out, _ = login(fp, "alice", pw["alice"], accept=False, tag="neg")
        check("SSO: login negado no provedor e recusado", rc != 0, out.strip()[-120:])
    finally:
        stop(p)
    a = (d / "audit.log").read_text()
    check("auditoria: oidc_auth com user=alice", '"oidc_auth"' in a and "alice" in a)
    check("auditoria e log sem token", "eyJ" not in a and "eyJ" not in (d / "srv.log").read_text())
    check("auditoria e log sem senha", all(v not in a for v in pw.values()))

    p, d, fp = server("grp", 'oidc_allowed_groups = ["suporte"]\n')
    try:
        rc, out, _ = login(fp, "bob", pw["bob"], tag="bob")
        check("SSO: bob (fora do grupo suporte) recusado", rc != 0 and "grupos" in out, out.strip()[-160:])
        rc, out, _ = login(fp, "alice", pw["alice"], tag="alice2")
        check("SSO: alice (grupo suporte) aceita", rc == 0, out.strip()[-160:])
    finally:
        stop(p)
    check("auditoria: oidc_auth_failed por grupo", "oidc_auth_failed" in (d / "audit.log").read_text())

    cfg = D / "notls.toml"
    cfg.write_text('listen = "127.0.0.1:5992"\ncapture = "test-pattern"\nsetup_done = true\n'
                   f'allow_no_auth = true\noidc_issuer = "{B}/realms/ti"\noidc_client_id = "openvnc"\n')
    r = subprocess.run([str(SRV), "-c", str(cfg)], capture_output=True, timeout=20)
    check("oidc sem require_tls: servidor recusa iniciar", r.returncode != 0)


try:
    certs()
    CTX = ssl.create_default_context(cafile=str(D / "ca.pem"))
    admin = secrets.token_urlsafe(16)
    keycloak(admin)
    tests(realm(admin))
finally:
    subprocess.run(["podman", "rm", "-f", NAME], capture_output=True)
    subprocess.run(["podman", "rmi", IMAGE], capture_output=True)
    shutil.rmtree(D, ignore_errors=True)
print(f"\n{sum(RES)}/{len(RES)} passaram")
sys.exit(0 if RES and all(RES) else 1)
