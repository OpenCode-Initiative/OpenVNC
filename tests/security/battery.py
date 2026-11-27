"""Bateria de seguranca ao vivo contra o openvnc-server (RFB/VeNCrypt).

Uso: python -I tests/security/battery.py CAMINHO/openvnc-server[.exe] [PASTA_TEMP]

Sobe servidores de teste (captura sintetica, so em 127.0.0.1, portas
5981-5985) e ataca cada um: sem TLS, senha errada, forca bruta, entrada
malformada, filtro de rede, auth_command (aceita, recusa, injecao, tempo
esgotado) e confere o log de auditoria. Senha aleatoria, nunca impressa.
"""
import os, secrets, tempfile, socket, ssl, struct, subprocess, sys, time, pathlib

HERE = pathlib.Path(__file__).resolve().parent
if len(sys.argv) < 2:
    sys.exit(__doc__)
EXE = pathlib.Path(sys.argv[1]).resolve()
S = pathlib.Path(sys.argv[2] if len(sys.argv) > 2 else tempfile.mkdtemp(prefix="openvnc-sec-")).resolve()
S.mkdir(parents=True, exist_ok=True)
PW = secrets.token_urlsafe(12)
RESULTS = []
sys.path.insert(0, str(HERE))
from vncdes import vnc_response


def check(name, ok, info=""):
    RESULTS.append((name, ok))
    print(("PASS " if ok else "FAIL ") + name + (f"  ({info})" if info else ""), flush=True)


def recvn(s, n):
    b = b""
    while len(b) < n:
        c = s.recv(n - len(b))
        if not c:
            raise ConnectionError("fechado")
        b += c
    return b


def hello(port):
    s = socket.create_connection(("127.0.0.1", port), timeout=10)
    v = recvn(s, 12)
    s.sendall(b"RFB 003.008\n")
    n = recvn(s, 1)[0]
    if n == 0:
        ln = struct.unpack(">I", recvn(s, 4))[0]
        return s, [], recvn(s, ln).decode(errors="replace")
    return s, list(recvn(s, n)), None


def plain_login(port, user, pw):
    """VeNCrypt X509Plain/TLSPlain. Devolve 'ok', 'fail' ou motivo."""
    try:
        s, types, reason = hello(port)
    except Exception as e:
        return f"recusado na abertura: {e}"
    if reason is not None:
        return f"recusado: {reason}"
    if 19 not in types:
        return f"sem VeNCrypt {types}"
    s.sendall(b"\x13")
    recvn(s, 2)
    s.sendall(b"\x00\x02")
    if recvn(s, 1)[0] != 0:
        return "versao VeNCrypt recusada"
    n = recvn(s, 1)[0]
    subs = struct.unpack(f">{n}I", recvn(s, 4 * n))
    vnc = user is None
    sub = (261 if 261 in subs else None) if vnc else (262 if 262 in subs else 259 if 259 in subs else None)
    if sub is None:
        return f"sem subtipo {subs}"
    s.sendall(struct.pack(">I", sub))
    if recvn(s, 1)[0] != 1:
        return "subtipo recusado"
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    t = ctx.wrap_socket(s, server_hostname="localhost")
    if vnc:
        try:
            ch = recvn(t, 16)
        except Exception as e:
            return f"fechado antes do desafio: {e}"
        t.sendall(vnc_response(pw, ch))
    else:
        u, p = user.encode(), pw.encode()
        t.sendall(struct.pack(">II", len(u), len(p)) + u + p)
    try:
        r = struct.unpack(">I", recvn(t, 4))[0]
    except Exception as e:
        return f"fechado apos credenciais: {e}"
    t.close()
    return "ok" if r == 0 else "fail"


def start(name, port, extra):
    d = S / name
    d.mkdir(exist_ok=True)
    cfg = d / "s.toml"
    cfg.write_text(
        f'listen = "127.0.0.1:{port}"\ncapture = "test-pattern"\nsetup_done = true\n'
        f'password_env = "OVNC_SEC_PW"\nrequire_tls = true\ntls_names = ["localhost"]\n'
        f'audit_log = "{(d / "audit.log").as_posix()}"\nstate_dir = "{d.as_posix()}"\n'
        f"ask_before_accept = false\n" + extra
    )
    env = dict(os.environ, OVNC_SEC_PW=PW)
    log = open(d / "srv.log", "w")
    p = subprocess.Popen([str(EXE), "-c", str(cfg)], env=env, stdout=log, stderr=log)
    for _ in range(100):
        try:
            socket.create_connection(("127.0.0.1", port), timeout=1).close()
            break
        except OSError:
            if p.poll() is not None:
                break
            time.sleep(0.2)
    time.sleep(1)  # deixa o servidor esquecer a sonda
    return p, d


def stop(p):
    p.terminate()
    p.wait(10)


def main():
    # 1. TLS obrigatorio, senha local, forca bruta, auditoria
    p, d = start("base", 5981, "")
    try:
        _, types, reason = hello(5981)
        check("sem TLS: servidor nao oferece None(1) nem VNC Auth(2) em claro",
              1 not in types and 2 not in types, f"tipos={types} {reason or ''}")
        check("senha correta aceita", plain_login(5981, None, PW) == "ok")
        check("senha errada recusada", plain_login(5981, None, "x" + PW) == "fail")
        check("usuario desconhecido recusado", plain_login(5981, "root", PW) != "ok")
        check("senha vazia recusada", plain_login(5981, None, "") != "ok")
        # protocolo malformado nao derruba o servidor
        s = socket.create_connection(("127.0.0.1", 5981), timeout=5)
        recvn(s, 12); s.sendall(b"GET / HTTP/1.1\r\n\r\n" + os.urandom(4096)); s.close()
        s = socket.create_connection(("127.0.0.1", 5981), timeout=5)
        check("entrada malformada nao derruba o servidor", recvn(s, 12).startswith(b"RFB"))
        s.close()
        res = [plain_login(5981, None, f"chute{i}") for i in range(6)]
        after = plain_login(5981, None, PW)
        check("forca bruta: apos 5 falhas o IP e bloqueado (ate a senha certa)",
              after != "ok", f"tentativas={res} depois={after}")
    finally:
        stop(p)
    a = (d / "audit.log").read_text(errors="replace")
    check("auditoria registra falhas e bloqueio", "auth_failed" in a and ("lock" in a or "block" in a),
          f"{len(a.splitlines())} linhas")
    check("auditoria nao contem a senha", PW not in a and PW not in (d / "srv.log").read_text(errors="replace"))

    # 2. filtro de rede
    p, d = start("net", 5982, 'allowed_networks = ["10.99.0.0/16"]\n')
    try:
        r = plain_login(5982, None, PW)
        check("IP fora de allowed_networks e recusado mesmo com senha certa", r != "ok", r)
    finally:
        stop(p)

    # 3. auth_command (diretorio corporativo simulado)
    auth = S / "auth.py"
    auth.write_text(
        "import os,sys\nu=os.environ.get('OPENVNC_USER','')\npw=sys.stdin.read()\n"
        "sys.exit(0 if (u=='alice' and pw=='S3nha-Corp!') else 1)\n")
    slow = S / "slow.py"
    slow.write_text("import time\ntime.sleep(30)\n")
    p, d = start("ext", 5983, f'auth_command = ["{sys.executable.replace(chr(92), "/")}", "-I", "{auth.as_posix()}"]\n')
    try:
        check("auth_command: usuario do diretorio com senha certa entra",
              plain_login(5983, "alice", "S3nha-Corp!") == "ok")
        check("auth_command: senha errada recusada", plain_login(5983, "alice", "errada") == "fail")
        r = plain_login(5983, "alice\nadmin", "S3nha-Corp!")
        check("auth_command: usuario com caractere de controle recusado", r != "ok", r)
        check("senha local (VNC Auth) continua valendo junto com auth_command",
              plain_login(5983, None, PW) == "ok")
    finally:
        stop(p)
    p, d = start("slow", 5984, f'auth_command = ["{sys.executable.replace(chr(92), "/")}", "-I", "{slow.as_posix()}"]\nauth_timeout_secs = 2\n')
    try:
        t0 = time.time()
        r = plain_login(5984, "alice", "x")
        check("auth_command lento: recusa por tempo esgotado (falha fechada)",
              r != "ok" and time.time() - t0 < 10, f"{r} em {time.time()-t0:.1f}s")
    finally:
        stop(p)

    # 4. auth_command sem TLS: servidor deve recusar iniciar
    d = S / "notls"; d.mkdir(exist_ok=True)
    cfg = d / "s.toml"
    cfg.write_text(f'listen = "127.0.0.1:5985"\ncapture = "test-pattern"\nsetup_done = true\n'
                   f'password_env = "OVNC_SEC_PW"\nrequire_tls = false\nauth_command = ["x"]\n')
    r = subprocess.run([str(EXE), "-c", str(cfg)], env=dict(os.environ, OVNC_SEC_PW=PW),
                       capture_output=True, timeout=20)
    check("auth_command sem require_tls: servidor recusa iniciar", r.returncode != 0)

    bad = [n for n, ok in RESULTS if not ok]
    print(f"\n{len(RESULTS) - len(bad)}/{len(RESULTS)} passaram")
    sys.exit(1 if bad else 0)


main()
