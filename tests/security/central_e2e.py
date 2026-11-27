"""Servidor central ponta a ponta: openvnc-central + openvnc-server + CLI --central.

Uso: python -I tests/security/central_e2e.py <dir com openvnc-central, openvnc-server e openvnc>

Nao precisa de container: o central gera a propria CA. Senhas e segredos
aleatorios ficam num diretorio temporario apagado ao final. Portas: central
em 127.0.0.1:8471, servidor em 5993 (RFB) e 5994 (nativo).
"""
import json, os, pathlib, secrets, shutil, ssl, subprocess, sys, tempfile, time
import urllib.error, urllib.request

EXT = ".exe" if os.name == "nt" else ""
T = pathlib.Path(sys.argv[1]).resolve()
CEN, SRV, CLI = T / f"openvnc-central{EXT}", T / f"openvnc-server{EXT}", T / f"openvnc{EXT}"
D = pathlib.Path(tempfile.mkdtemp(prefix="ovnc-central-"))
B = "https://localhost:8471"
CCFG = D / "central.toml"
RES = []
SECRETS = []


def check(n, ok, info=""):
    RES.append(ok)
    print(("PASS " if ok else "FAIL ") + n + (f"  ({info})" if info else ""), flush=True)


def central(*a, pw=None):
    env = dict(os.environ)
    if pw is not None:
        env["OPENVNC_CENTRAL_PASSWORD"] = pw
    r = subprocess.run([str(CEN), "-c", str(CCFG), *a], capture_output=True, text=True, env=env, timeout=60)
    if r.returncode != 0:
        raise RuntimeError(f"openvnc-central {a[:2]}: {r.stderr.strip()[-200:]}")
    return r.stdout


def api(m, path, body=None, tok=None):
    h, data = {}, None
    if tok:
        h["Authorization"] = "Bearer " + tok
    if body is not None:
        data, h["Content-Type"] = json.dumps(body).encode(), "application/json"
    try:
        r = urllib.request.urlopen(urllib.request.Request(B + path, data, h, method=m), context=CTX, timeout=10)
        return r.status, json.loads(r.read() or b"null")
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read() or b"null")


def setup():
    CCFG.write_text(f'listen = "127.0.0.1:8471"\nissuer = "{B}"\nstate_dir = "{(D / "cstate").as_posix()}"\n'
                    f'audit_log = "{(D / "central-audit.log").as_posix()}"\n')
    central("init")
    central("export-ca", "--out", str(D / "ca.pem"))
    pw = {u: secrets.token_urlsafe(12) for u in ("alice", "carol", "dave", "root")}
    SECRETS.extend(pw.values())
    central("group", "add", "suporte")
    central("user", "add", "alice", "--group", "suporte", pw=pw["alice"])
    central("user", "add", "carol", pw=pw["carol"])
    central("user", "add", "dave", pw=pw["dave"])
    central("user", "add", "root", "--admin", pw=pw["root"])
    return pw


def server(fp_holder):
    d = D / "srv"
    d.mkdir()
    cfg = d / "s.toml"
    base = (f'listen = "127.0.0.1:5993"\nnative_listen = "127.0.0.1:5994"\ncapture = "test-pattern"\n'
            f'setup_done = true\nrequire_tls = true\ntls_names = ["localhost"]\nask_before_accept = false\n'
            f'audit_log = "{(d / "audit.log").as_posix()}"\nstate_dir = "{d.as_posix()}"\n'
            f'oidc_issuer = "{B}"\noidc_client_id = "openvnc"\noidc_ca = "{(D / "ca.pem").as_posix()}"\n'
            f'central_machine_id = "pc-01"\ncentral_url = "{B}"\ncentral_secret_env = "OVNC_E2E_SECRET"\n')
    cfg.write_text(base)
    fp = subprocess.run([str(SRV), "-c", str(cfg), "fingerprint"], capture_output=True, text=True).stdout.strip()
    out = central("machine", "add", "pc-01", "--name", "PC 01", "--address", "127.0.0.1", "--port", "5994",
                  "--fingerprint", fp)
    secret = out.strip().splitlines()[-1].strip()
    SECRETS.append(secret)
    # mesma porta, outro id: o ticket de pc-02 chega no servidor pc-01
    out2 = central("machine", "add", "pc-02", "--name", "PC 02", "--address", "127.0.0.1", "--port", "5994",
                   "--fingerprint", fp)
    SECRETS.append(out2.strip().splitlines()[-1].strip())
    central("grant", "--group", "suporte", "--machine", "pc-01", "--perms", "view,control,files")
    central("grant", "--user", "carol", "--machine", "pc-01", "--perms", "view")
    central("grant", "--user", "alice", "--machine", "pc-02", "--perms", "view,control")
    log = open(d / "srv.log", "w")
    p = subprocess.Popen([str(SRV), "-c", str(cfg)], stdout=log, stderr=log,
                         env=dict(os.environ, OVNC_E2E_SECRET=secret))
    time.sleep(3)
    return p, d


def connect(user, pw, machine, tag, nudge=False):
    out = D / f"shot-{tag}.png"
    a = [str(CLI), "native", machine, "--central", B, "--central-ca", str(D / "ca.pem"), "--user", user,
         "--transport", "tcp", "-o", str(out), "--timeout", "30"]
    if nudge:
        a.append("--nudge")
    r = subprocess.run(a, capture_output=True, text=True, timeout=90,
                       env=dict(os.environ, OPENVNC_CENTRAL_PASSWORD=pw))
    return r.returncode, r.stdout + r.stderr, out.exists()


def tests(pw):
    st, v = api("GET", "/.well-known/openid-configuration")
    check("descoberta OIDC no central", bool(st == 200 and v.get("issuer") == B and v.get("jwks_uri")))
    st, _ = api("POST", "/api/login", {"user": "alice", "password": "errada-errada"})
    check("login com senha errada recusado", st == 401, str(st))
    p, d = server(None)
    try:
        r = subprocess.run([str(CLI), "central-login", B, "--user", "alice", "--ca", str(D / "ca.pem")],
                           capture_output=True, text=True, timeout=30,
                           env=dict(os.environ, OPENVNC_CENTRAL_PASSWORD=pw["alice"]))
        check("CLI central-login lista as maquinas da alice", r.returncode == 0 and "pc-01" in r.stdout
              and "pc-02" in r.stdout, r.stdout.strip()[-160:])
        rc, out, shot = connect("alice", pw["alice"], "pc-01", "alice")
        check("alice (grupo suporte, control) conecta", rc == 0 and shot, out.strip()[-200:])
        rc, out, _ = connect("dave", pw["dave"], "pc-01", "dave")
        check("dave (sem concessao) recusado", rc != 0 and "nao liberada" in out, out.strip()[-160:])
        st, tok = api("POST", "/api/login", {"user": "dave", "password": pw["dave"]})
        st2, _ = api("POST", "/api/ticket", {"machine": "pc-01"}, tok and tok.get("session"))
        check("central nega ticket ao dave", st == 200 and st2 == 403, f"{st}/{st2}")
        rc, out, shot = connect("carol", pw["carol"], "pc-01", "carol", nudge=True)
        check("carol (so view) conecta e envia entrada", rc == 0 and shot, out.strip()[-200:])
        rc, out, _ = connect("alice", pw["alice"], "pc-02", "wrong")
        check("ticket de outra maquina recusado", rc != 0 and "outra maquina" in out, out.strip()[-160:])
        time.sleep(3)
        st, tok = api("POST", "/api/login", {"user": "root", "password": pw["root"]})
        st2, aud = api("GET", "/api/audit?limit=500", tok=tok.get("session"))
        st3, _ = api("GET", "/api/audit", tok=api("POST", "/api/login",
                                                  {"user": "carol", "password": pw["carol"]})[1]["session"])
        check("auditoria central so para admin", st2 == 200 and st3 == 403, f"{st2}/{st3}")
    finally:
        p.terminate()
        p.wait(10)
    a = (d / "audit.log").read_text()
    ca = (D / "central-audit.log").read_text()
    check("local: carol com perms=view e input_denied",
          '"perms":"view"' in a.replace(" ", "") and "input_denied" in a and "carol" in a)
    check("local: alice com perms view,control,files", "view,control,files" in a)
    check("local: oidc_auth_failed para outra maquina", "oidc_auth_failed" in a and "outra maquina" in a)
    check("central: tickets e login registrados", "central_ticket" in ca and "central_login" in ca)
    check("central: eventos encaminhados pelo servidor", '"remote"' in ca and "input_denied" in ca
          and "session_perms" in ca)
    st = json.dumps(aud)
    check("central: GET /api/audit traz eventos remotos", "remote" in st)
    logs = a + ca + (d / "srv.log").read_text()
    check("logs sem token (eyJ)", "eyJ" not in logs)
    check("logs sem senhas nem segredo da maquina", all(s not in logs for s in SECRETS))


cp = None
try:
    pw = setup()
    CTX = ssl.create_default_context(cafile=str(D / "ca.pem"))
    clog = open(D / "central.log", "w")
    cp = subprocess.Popen([str(CEN), "-c", str(CCFG), "serve"], stdout=clog, stderr=clog)
    time.sleep(2)
    tests(pw)
    check("log do central sem segredos", all(s not in (D / "central.log").read_text() for s in SECRETS))
finally:
    if cp:
        cp.terminate()
        cp.wait(10)
    shutil.rmtree(D, ignore_errors=True)
print(f"\n{sum(RES)}/{len(RES)} passaram")
sys.exit(0 if RES and all(RES) else 1)
