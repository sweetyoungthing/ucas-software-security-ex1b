"""Rebuild and verify EX1B against a fresh local TLS deployment."""

import argparse
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager, ExitStack
import hashlib
import json
from pathlib import Path
import platform
import select
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time

from client import Client, RemoteError, TransferInterrupted
import protocol as p
from server import DISK_QUOTA, HANDSHAKE_TIMEOUT, MAX_CONNECTIONS, MAX_USER_SESSIONS
from setup_lab import ACCOUNTS, issue, make_ca


SOURCE = Path(__file__).resolve().parent
HOST = "127.0.0.1"


def check(condition, description):
    if not condition:
        raise AssertionError(description)


@contextmanager
def rejected(*exceptions):
    try:
        yield
    except exceptions:
        return
    raise AssertionError("request unexpectedly succeeded")


@contextmanager
def deployment(state):
    with subprocess.Popen(
        [sys.executable, "-u", "server.py", "--state", str(state), "--port", "0"],
        cwd=SOURCE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
    ) as server:
        try:
            check(select.select([server.stdout], [], [], 10)[0], "server startup timed out")
            ready = server.stdout.readline().strip()
            check(ready.startswith("READY "), f"server startup failed: {ready}")
            print(f"$ python3 server.py --state ./lab-state --port 0\n{ready}", flush=True)
            yield int(ready.split()[1])
        finally:
            server.terminate()
            try:
                server.wait(timeout=5)
            except subprocess.TimeoutExpired:
                server.kill()
                server.wait()


def secure_socket(state, port, user=None, hostname=HOST, trust=None):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.load_verify_locations(trust or state / "server" / "ca.pem")
    if user:
        creds = state / "clients" / user
        ctx.load_cert_chain(creds / "cert.pem", creds / "key.pem")
    with socket.create_connection((HOST, port), timeout=5) as raw:
        return ctx.wrap_socket(raw, server_hostname=hostname)


def command(sock, op, data=None, *, expected=p.OK, rid=1):
    payload = data if isinstance(data, bytes) else p.encode_json(data or {})
    p.send_frame(sock, op, rid, payload)
    frame = p.recv_frame(sock)
    check((frame.op, frame.rid) == (expected, rid), f"unexpected response {frame}")
    return p.decode_json(frame.payload) if frame.op != p.DATA else frame.payload


def interrupt_after_first(done, total):
    if 0 < done < total:
        raise TransferInterrupted("controlled disconnect after first chunk")


def exercise(root, state, port, record, transfer_only=False):
    sample = root / "sample.bin"
    sample.write_bytes(hashlib.shake_256(b"EX1B verified fixture").digest(2 * p.CHUNK + 313))
    contents = sample.read_bytes()
    size = len(contents)
    digest = hashlib.sha256(contents).hexdigest()

    def connect(user="alice"):
        return Client(state, user, port=port)

    with connect() as alice:
        check(alice.tls_version == "TLSv1.3" and alice.info["user"] == "alice", "TLS or identity")
        record("双向认证", f"TLSv1.3 握手完成，HELLO 返回 alice；限速 {alice.info['rate'] // 2**20} MiB/s")
        start = time.monotonic()
        local = alice.local_address
        alice.list_files()
        time.sleep(p.FRAME_TIMEOUT + 1)
        alice.ping()
        check(local == alice.local_address, "connection changed during idle")
        record("长连接和心跳", f"空闲 {time.monotonic() - start:.1f} 秒后同一 TCP 本地端口 {local[1]} 响应 PING")

        downloaded = root / "round-trip.bin"
        upload = alice.upload(sample, "示例.bin")
        listed = alice.list_files()
        receipt = alice.download("示例.bin", downloaded)
        check(upload["sha256"] == receipt["sha256"] == digest, "round-trip hash")
        check(downloaded.read_bytes() == contents, "round-trip content")
        check({"name": "示例.bin", "size": size} in listed, "file absent from list")
        record("上传、列目录与下载", f"{size:,} B 往返逐字节一致\nSHA-256 {digest}")

        empty = root / "empty.bin"
        empty.touch()
        alice.upload(empty)
        check(alice.download(empty.name, root / "download-empty.bin")["size"] == 0, "empty file")
        record("零字节文件", "无数据帧，上传和下载均完成大小及摘要确认")

    with connect() as alice:
        with rejected(TransferInterrupted):
            alice.upload(sample, "resume.bin", interrupt_after_first)
    with connect() as alice:
        receipt = alice.upload(sample, "resume.bin")
        check(receipt["offset"] == p.CHUNK and receipt["sha256"] == digest, "upload resume")
        record("上传断点续传", f"断开 TLS 后重新连接，服务端返回偏移 {receipt['offset']:,} B")
        target = root / "resumed.bin"
        with rejected(TransferInterrupted):
            alice.download("resume.bin", target, interrupt_after_first)
        check(not target.exists(), "partial was published")
    with connect() as alice:
        receipt = alice.download("resume.bin", target)
        check(receipt["offset"] == p.CHUNK and target.read_bytes() == contents, "download resume")
        record("下载断点续传", f"新连接从 {receipt['offset']:,} B 继续；完整校验后才发布本地文件")

    fixture = root / "parallel.bin"
    fixture.write_bytes(contents * 8)
    begin = threading.Barrier(3)

    def parallel_upload(user, name):
        def progress(done, total):
            if done == 0:
                begin.wait(timeout=8)

        with connect(user) as client:
            start = time.monotonic()
            result = client.upload(fixture, name, progress)
            return result, client.local_address[1], time.monotonic() - start

    jobs = [("alice", "a.bin"), ("alice", "b.bin"), ("bob", "c.bin")]
    with ThreadPoolExecutor(max_workers=len(jobs)) as pool:
        tasks = [pool.submit(parallel_upload, *job) for job in jobs]
        results = [task.result(timeout=15) for task in tasks]
    check(len({port for _, port, _ in results}) == 3, "distinct sessions")
    for user, name in jobs:
        check((state / "storage" / user / name).read_bytes() == fixture.read_bytes(), "concurrent upload")
    record("两用户、三会话并发", f"三任务同时进入上传状态，各传 {fixture.stat().st_size:,} B 并通过字节校验")
    check(results[2][2] >= fixture.stat().st_size / (2 * 2**20) - 0.02, "Bob transfer rate")
    record("按用户限速", f"Bob {fixture.stat().st_size:,} B 耗时 {results[2][2]:.3f} 秒，符合 2 MiB/s 配置")

    if transfer_only:
        return

    with connect("bob") as bob:
        check({item["name"] for item in bob.list_files()} == {"c.bin"}, "Bob can see Alice files")
        with rejected(RemoteError):
            bob.download("a.bin", root / "denied.bin")
        bob.ping()
    with secure_socket(state, port, "alice") as wire:
        command(wire, p.HELLO)
        for bad in ("../bob/c.bin", "/etc/passwd"):
            response = command(wire, p.GET_BEGIN, {"name": bad, "offset": 0, "sha256": ""},
                               expected=p.ERROR)
            check("filename" in response["error"], "missing filename rejection")
        literal = command(wire, p.GET_BEGIN, {"name": "' OR 1=1 --", "offset": 0, "sha256": ""},
                          expected=p.ERROR)
        check(literal["error"] == "file not found", "SQL-like input was not a literal filename")
        command(wire, p.BYE)
    record("ACL 与异常输入", "Bob 无法列出或读取 Alice 的文件；拒绝路径穿越、绝对路径；SQL 风格输入只作文件名")

    with secure_socket(state, port, "alice") as wire:
        command(wire, p.HELLO)
        command(wire, p.PUT_BEGIN, {"name": "a.bin", "size": 4, "sha256": "0" * 64})
        command(wire, p.PUT_CHUNK, b"oops")
        failure = command(wire, p.PUT_END, expected=p.ERROR)
        check("SHA-256" in failure["error"], "mismatched digest")
        check((state / "storage" / "alice" / "a.bin").read_bytes() == fixture.read_bytes(),
              "failed upload overwrote the target")
        command(wire, p.BYE)
        check(wire.recv(1) == b"", "BYE did not close the server socket")
    record("摘要错误与正常退出", "错误 SHA-256 被拒且旧文件保持不变；BYE 收到 OK 后服务端关闭连接")

    wrong_ca = root / "wrong-ca"
    wrong_ca.mkdir(mode=0o700)
    make_ca(wrong_ca)
    unlisted = state / "clients" / "unlisted"
    unlisted.mkdir(mode=0o700)
    issue(state / "issuer", unlisted, "unlisted")
    with rejected(ssl.SSLCertVerificationError):
        with secure_socket(state, port, "alice", trust=wrong_ca / "ca.pem"):
            pass
    with rejected(ssl.SSLCertVerificationError):
        with secure_socket(state, port, "alice", hostname="wrong.example"):
            pass
    for user in (None, "unlisted"):
        with rejected(ssl.SSLError, EOFError, ConnectionResetError):
            with secure_socket(state, port, user) as wire:
                command(wire, p.HELLO)
    record("证书负例", "错误 CA、错误主机名、未提供客户端证书、受信 CA 签发但未列入白名单均被拒绝")

    with secure_socket(state, port, "alice") as wire:
        wire.sendall(p.HEADER.pack(p.MAGIC, p.VERSION, p.HELLO, 0, 1, p.MAX_JSON + 1))
        check(wire.recv(1) == b"", "oversized frame accepted")
    with connect() as alice:
        alice.ping()
    record("超长帧", "只发送声明 32769 B 的控制帧头，服务端立即关闭该连接；新连接正常")

    store = state / "storage" / "bob"
    allocation = DISK_QUOTA - (store / "c.bin").stat().st_size
    with (store / ".quota-test").open("wb") as sparse:
        sparse.truncate(allocation)
    with connect("bob") as bob:
        with rejected(RemoteError):
            bob.upload(sample)
        bob.ping()
    (store / ".quota-test").unlink()
    record("磁盘配额", "用稀疏文件将 Bob 逻辑占用设为 256 MiB，新的上传在开始前被拒绝")

    with ExitStack() as stack:
        for _ in range(MAX_USER_SESSIONS):
            stack.enter_context(connect())
        with rejected(EOFError, OSError):
            with connect():
                pass
        with connect("bob") as bob:
            bob.ping()
    record("单账户连接上限", f"Alice 第 {MAX_USER_SESSIONS + 1} 条连接被拒，Bob 仍可访问")

    time.sleep(0.2)
    with ExitStack() as stack:
        for _ in range(MAX_CONNECTIONS):
            stack.enter_context(socket.create_connection((HOST, port), timeout=2))
        with socket.create_connection((HOST, port), timeout=2) as extra:
            check(extra.recv(1) == b"", "global admission did not close excess connection")
        time.sleep(HANDSHAKE_TIMEOUT + 0.3)
        with connect() as alice:
            alice.ping()
    record("全局连接上限与超时回收",
           f"第 {MAX_CONNECTIONS + 1} 条连接被立即拒绝；{HANDSHAKE_TIMEOUT} 秒握手超时后可重新认证")


def exercise_duplex(root, state, port, record):
    size = 4 * 2**20
    payload = hashlib.shake_256(b"EX1B bidirectional fixture").digest(size)
    digest = hashlib.sha256(payload).hexdigest()
    source = root / "duplex.bin"
    source.write_bytes(payload)
    users = ("alice", "bob")
    jobs = [(user, direction) for user in users for direction in ("put", "get")]
    started_at = []
    ready = threading.Barrier(len(jobs), action=lambda: started_at.append(time.monotonic()))

    def seed(user):
        with Client(state, user, port=port) as client:
            client.upload(source, "duplex-source.bin")

    def transfer(user, direction):
        first_chunk_at = None
        last_chunk_at = None

        def on_progress(done, total):
            nonlocal first_chunk_at, last_chunk_at
            if done == 0:
                ready.wait(timeout=8)
            else:
                when = time.monotonic()
                if first_chunk_at is None:
                    first_chunk_at = when
                if done == total:
                    last_chunk_at = when

        with Client(state, user, port=port) as client:
            check(client.info["rate"] == ACCOUNTS[user], f"{user}: wrong account rate")
            if direction == "put":
                result = client.upload(source, "duplex-upload.bin", on_progress)
                target = state / "storage" / user / "duplex-upload.bin"
            else:
                target = root / f"{user}-duplex-download.bin"
                result = client.download("duplex-source.bin", target, on_progress)
            check(result == {"size": size, "sha256": digest, "offset": 0}, "duplex transfer receipt")
            check(target.read_bytes() == payload, "duplex transfer content")
            check(first_chunk_at is not None and last_chunk_at is not None, "missing duplex progress")
            return client.local_address[1], first_chunk_at, last_chunk_at

    with ThreadPoolExecutor(max_workers=len(jobs)) as pool:
        list(pool.map(seed, users))
        tasks = {job: pool.submit(transfer, *job) for job in jobs}
        results = {job: task.result(timeout=30) for job, task in tasks.items()}

    check(len({port for port, _, _ in results.values()}) == len(jobs), "distinct duplex sessions")
    overlap = min(last for _, _, last in results.values()) - max(
        first for _, first, _ in results.values()
    )
    check(overlap > 0, "the four transfers did not overlap in payload time")
    record("两上传与两下载同时进行",
           f"四条 TLS 会话的有效数据传输重叠 {overlap:.3f} 秒；每个文件 {size:,} B，四份均逐字节一致")

    elapsed = {}
    rate_notes = []
    for user in users:
        elapsed[user] = max(results[user, direction][2] for direction in ("put", "get")) - started_at[0]
        configured = ACCOUNTS[user] / 2**20
        ideal_minimum = 2 * size / ACCOUNTS[user]
        check(elapsed[user] >= ideal_minimum - 0.05, f"{user}: aggregate rate exceeded")
        rate_notes.append(
            f"{user} 双向共 {2 * size // 2**20} MiB 用时 {elapsed[user]:.3f} 秒，"
            f"平均 {2 * size / 2**20 / elapsed[user]:.2f} MiB/s，配置 {configured:g} MiB/s"
        )
    check(elapsed["alice"] < elapsed["bob"], "different account caps were not observed")
    record("按身份限制双向聚合带宽", "；".join(rate_notes))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence", type=Path, help="write observed test evidence as JSON")
    parser.add_argument("--transfer-only", action="store_true",
                        help="run normal file-transfer, authentication, concurrency and bandwidth checks")
    args = parser.parse_args()
    environment = f"{platform.platform()} · Python {platform.python_version()} · {ssl.OPENSSL_VERSION}"
    results = []

    def record(case, observed):
        results.append({"case": case, "observed": observed})
        print(f"PASS  {case}\n      {observed.replace(chr(10), chr(10) + '      ')}", flush=True)

    print(environment, flush=True)
    with tempfile.TemporaryDirectory(prefix="ex1b-verify-") as directory:
        root = Path(directory)
        state = root / "lab-state"
        print("$ python3 -m compileall -q .", flush=True)
        subprocess.run([sys.executable, "-m", "compileall", "-q", "."], cwd=SOURCE, check=True)
        print("$ python3 setup_lab.py --state ./lab-state", flush=True)
        subprocess.run([sys.executable, "setup_lab.py", "--state", str(state)], cwd=SOURCE, check=True)
        with deployment(state) as port:
            exercise(root, state, port, record, args.transfer_only)
            exercise_duplex(root, state, port, record)
    print(f"PASS  {len(results)}/{len(results)} 项端到端检查", flush=True)
    if args.evidence:
        args.evidence.write_text(json.dumps({
            "environment": environment,
            "build": "python3 -m compileall -q . 退出码为 0",
            "verify_command": (
                "python3 verify.py --transfer-only --evidence ../evidence.json" if args.transfer_only
                else "python3 verify.py --evidence ../evidence.json"
            ),
            "results": results,
        }, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
