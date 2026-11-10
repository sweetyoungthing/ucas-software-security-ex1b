"""Provision an isolated lab CA, certificate allowlist, and storage ACLs."""

import argparse
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import shutil
import ssl
import subprocess


ACCOUNTS = {"alice": 8 * 1024**2, "bob": 2 * 1024**2}


def openssl(*args):
    subprocess.run(["openssl", *map(str, args)], check=True, stdout=subprocess.DEVNULL)


def make_key(path):
    openssl("genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256",
            "-out", path)
    path.chmod(0o600)


def make_ca(issuer):
    key = issuer / "ca-key.pem"
    cert = issuer / "ca.pem"
    make_key(key)
    openssl("req", "-new", "-x509", "-sha256", "-days", "90", "-key", key,
            "-subj", "/CN=EX1B Lab CA", "-out", cert,
            "-addext", "basicConstraints=critical,CA:TRUE,pathlen:0",
            "-addext", "keyUsage=critical,keyCertSign,cRLSign")


def issue(issuer, output, name, *, server_sans=()):
    """Issue a TLS identity; the issuer's private key stays outside output."""
    key = output / "key.pem"
    cert = output / "cert.pem"
    csr = output / "request.csr"
    extensions = output / "extensions.cnf"
    make_key(key)
    openssl("req", "-new", "-sha256", "-key", key, "-subj", f"/CN={name}", "-out", csr)
    usage = "serverAuth" if server_sans else "clientAuth"
    settings = ("basicConstraints=critical,CA:FALSE\n"
                "keyUsage=critical,digitalSignature\n"
                f"extendedKeyUsage={usage}\n"
                "subjectKeyIdentifier=hash\n"
                "authorityKeyIdentifier=keyid,issuer\n")
    if server_sans:
        settings += "subjectAltName=" + ",".join(server_sans) + "\n"
    extensions.write_text(settings, encoding="ascii")
    openssl("x509", "-req", "-days", "30", "-sha256", "-in", csr, "-out", cert,
            "-CA", issuer / "ca.pem", "-CAkey", issuer / "ca-key.pem",
            "-set_serial", "0x" + os.urandom(16).hex(), "-extfile", extensions)
    csr.unlink()
    extensions.unlink()
    shutil.copyfile(issuer / "ca.pem", output / "ca.pem")
    return hashlib.sha256(ssl.PEM_cert_to_DER_cert(cert.read_text())).hexdigest()


def add_san(value):
    try:
        return f"IP:{ipaddress.ip_address(value)}"
    except ValueError:
        if len(value) <= 253 and all(
            re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?", part)
            for part in value.split(".")
        ):
            return "DNS:" + value
        raise argparse.ArgumentTypeError("expected a DNS name or IP address") from None


def provision(state, extra_sans=()):
    if os.name != "posix":
        raise RuntimeError("the server ACL requires a POSIX host")
    if not ssl.HAS_TLSv1_3:
        raise RuntimeError("the Python ssl module must support TLS 1.3")
    if not shutil.which("openssl"):
        raise RuntimeError("OpenSSL CLI is required to issue the lab certificates")

    previous_umask = os.umask(0o077)
    try:
        state.mkdir(mode=0o700)
        try:
            for folder in ("issuer", "server", "clients", "storage"):
                (state / folder).mkdir(mode=0o700)
            make_ca(state / "issuer")
            issue(state / "issuer", state / "server", "localhost",
                  server_sans=("DNS:localhost", "IP:127.0.0.1", *extra_sans))
            users = {}
            for user, rate in ACCOUNTS.items():
                output = state / "clients" / user
                output.mkdir(mode=0o700)
                (state / "storage" / user).mkdir(mode=0o700)
                digest = issue(state / "issuer", output, user)
                users[digest] = {"name": user, "rate": rate}
            (state / "server" / "users.json").write_text(
                json.dumps(users, indent=2) + "\n", encoding="utf-8"
            )
        except BaseException:
            shutil.rmtree(state)
            raise
    finally:
        os.umask(previous_umask)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state", required=True, type=Path,
                        help="new directory for local keys, policy and data")
    parser.add_argument("--server-name", action="append", default=[], type=add_san,
                        help="additional hostname or IP for the server certificate")
    args = parser.parse_args()
    try:
        provision(args.state, args.server_name)
    except (OSError, RuntimeError, subprocess.CalledProcessError) as error:
        parser.exit(1, f"Setup failed: {error}\n")
    print("Provisioned local CA, server certificate, and two client identities.")
    for user, rate in ACCOUNTS.items():
        print(f"  {user}: {rate // 1024**2} MiB/s; storage/{user} mode 0700")
    print(f"State: {args.state}")


if __name__ == "__main__":
    main()
