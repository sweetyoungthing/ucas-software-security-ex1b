"""SFT/1 client and interactive command line."""

import argparse
from contextlib import contextmanager
import hashlib
import os
from pathlib import Path
import re
import shlex
import socket
import ssl
import stat
import threading
import unicodedata

from protocol import (
    BYE, CHUNK, DATA, ERROR, GET_BEGIN, GET_CHUNK, GET_END, HELLO, LIST,
    MAX_FILE, OK, PING, PUT_BEGIN, PUT_CHUNK, PUT_END, ProtocolError,
    decode_json, encode_json, keepalive, recv_frame, send_frame, valid_digest,
    valid_name,
)

_TARGETS = set()
_TARGETS_LOCK = threading.Lock()


class RemoteError(Exception):
    """The server returned an application error."""


class TransferInterrupted(Exception):
    """The local application stopped a transfer at a chunk boundary."""


def _bounded_int(value, lower, upper):
    return type(value) is int and lower <= value <= upper


def _private_file(path, *, create=True):
    flags = os.O_RDWR | (os.O_CREAT if create else 0)
    flags |= getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    if path.is_symlink():
        raise ValueError(f"拒绝符号链接形式的续传文件 {path}")
    fd = os.open(path, flags, 0o600)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise ValueError(f"续传路径必须是单一链接的普通文件 {path}")
        return os.fdopen(fd, "r+b")
    except BaseException:
        os.close(fd)
        raise


@contextmanager
def _reserve_target(target):
    # GUI channels can be active concurrently. Avoid two writers for one destination.
    key = unicodedata.normalize("NFC", str(target).casefold())
    with _TARGETS_LOCK:
        if key in _TARGETS:
            raise ValueError(f"该目标正在下载 {target}")
        _TARGETS.add(key)
    try:
        yield
    finally:
        with _TARGETS_LOCK:
            _TARGETS.remove(key)


class Client:
    """One mutually authenticated connection, with requests serialized on the wire."""

    def __init__(self, state, user, host="127.0.0.1", port=9443, *, heartbeat=5.0):
        if not isinstance(user, str) or not re.fullmatch(r"[a-z][a-z0-9_-]{0,31}", user):
            raise ValueError("用户 ID 无效")
        if heartbeat <= 0:
            raise ValueError("心跳间隔必须大于零")
        self.host, self.port, self.user = host, port, user
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._rid = 0
        credentials = Path(state) / "clients" / user
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.minimum_version = ssl.TLSVersion.TLSv1_3
        context.load_verify_locations(cafile=str(credentials / "ca.pem"))
        context.load_cert_chain(credentials / "cert.pem", credentials / "key.pem")
        with socket.create_connection((host, port), timeout=8) as raw:
            keepalive(raw)
            self._sock = context.wrap_socket(raw, server_hostname=host)
        try:
            self.tls_version = self._sock.version()
            self.peer_fingerprint = hashlib.sha256(self._sock.getpeercert(binary_form=True)).hexdigest()
            self.local_address = self._sock.getsockname()
            self.info = self._control(HELLO)
            if self.info.get("user") != user or not _bounded_int(
                self.info.get("rate"), 1, 2**63 - 1
            ):
                raise ProtocolError("HELLO 返回的身份或限速无效")
        except BaseException:
            self._abort()
            raise
        self._heartbeat = threading.Thread(
            target=self._heartbeat_loop, args=(heartbeat,), name=f"sft-heartbeat-{user}",
            daemon=True,
        )
        self._heartbeat.start()

    @property
    def connected(self):
        return not self._stop.is_set()

    def _abort(self):
        self._stop.set()
        try:
            self._sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        self._sock.close()

    def _exchange(self, op, payload, response_op):
        if not self.connected:
            raise ConnectionError("连接已关闭")
        self._rid = self._rid % 0xFFFFFFFF + 1
        try:
            send_frame(self._sock, op, self._rid, payload)
            frame = recv_frame(self._sock)
            if frame.rid != self._rid:
                raise ProtocolError("响应的请求编号不匹配")
            if frame.op == ERROR:
                error = decode_json(frame.payload).get("error")
                if not isinstance(error, str):
                    raise ProtocolError("ERROR 响应缺少错误描述")
                raise RemoteError(error)
            if frame.op != response_op:
                raise ProtocolError("响应的报文类型不匹配")
            if response_op == DATA:
                return frame.payload
            return decode_json(frame.payload)
        except (ProtocolError, OSError, EOFError, KeyboardInterrupt):
            self._abort()
            raise

    def _control(self, op, data=None):
        return self._exchange(op, encode_json({} if data is None else data), OK)

    def _heartbeat_loop(self, interval):
        while not self._stop.wait(interval):
            if not self._lock.acquire(blocking=False):
                continue
            try:
                self._control(PING)
            except (ProtocolError, OSError, EOFError, RemoteError):
                self._abort()
            finally:
                self._lock.release()

    @contextmanager
    def _transfer(self):
        with self._lock:
            try:
                yield
            except RemoteError:
                # On ERROR the server releases any transfer associated with this session.
                raise
            except BaseException:
                # The server may still be expecting data or an acknowledgement.
                self._abort()
                raise

    def ping(self):
        with self._lock:
            self._control(PING)

    def list_files(self):
        with self._lock:
            files = self._control(LIST).get("files")
            if not isinstance(files, list) or any(
                not isinstance(item, dict)
                or not valid_name(item.get("name"))
                or not _bounded_int(item.get("size"), 0, MAX_FILE)
                for item in files
            ):
                self._abort()
                raise ProtocolError("LIST 响应包含无效文件信息")
            return files

    def upload(self, source, name=None, progress=None):
        source = Path(source)
        name = unicodedata.normalize("NFC", source.name) if name is None else name
        if not valid_name(name):
            raise ValueError(f"远程文件名无效 {name!r}")
        if not source.is_file():
            raise ValueError("上传源必须是普通文件")

        with source.open("rb") as file:
            info = os.fstat(file.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_FILE:
                raise ValueError(f"上传源必须是普通文件且不超过 {MAX_FILE // 2**20} MiB")
            size = info.st_size
            digest = hashlib.sha256()
            remaining = size
            while remaining:
                data = file.read(min(CHUNK, remaining))
                if not data:
                    raise ValueError("计算摘要期间源文件长度发生变化")
                digest.update(data)
                remaining -= len(data)
            if file.read(1):
                raise ValueError("计算摘要期间源文件长度发生变化")
            sha256 = digest.hexdigest()

            with self._transfer():
                begin = self._control(PUT_BEGIN, {"name": name, "size": size, "sha256": sha256})
                offset = begin.get("offset")
                if not _bounded_int(offset, 0, size):
                    raise ProtocolError("PUT_BEGIN 返回的偏移无效")
                file.seek(offset)
                done = offset
                if progress:
                    progress(done, size)
                while done < size:
                    data = file.read(min(CHUNK, size - done))
                    if not data:
                        raise ValueError("传输期间源文件长度发生变化")
                    ack = self._exchange(PUT_CHUNK, data, OK).get("offset")
                    done += len(data)
                    if type(ack) is not int or ack != done:
                        raise ProtocolError("PUT_CHUNK 确认的偏移不匹配")
                    if progress:
                        progress(done, size)
                if file.read(1):
                    raise ValueError("传输期间源文件长度发生变化")
                receipt = self._control(PUT_END)
                if (
                    type(receipt.get("size")) is not int
                    or receipt.get("size") != size
                    or receipt.get("sha256") != sha256
                ):
                    raise ProtocolError("PUT_END 回执与原文件不匹配")
        return {"size": size, "sha256": sha256, "offset": offset}

    def download(self, name, destination, progress=None):
        if not valid_name(name):
            raise ValueError(f"远程文件名无效 {name!r}")
        destination = Path(destination)
        target = destination.parent.resolve(strict=True) / destination.name
        if target.is_dir():
            raise ValueError(f"目标应为文件路径 {target}")
        scope = encode_json({
            "host": self.host, "port": self.port, "server": self.peer_fingerprint,
            "user": self.user, "remote": name, "local": target.name,
        })
        tag = hashlib.sha256(scope).hexdigest()
        part = target.with_name(f".sft-{tag}.part")
        metadata = target.with_name(f".sft-{tag}.sha256")
        with _reserve_target(target), self._transfer():
            offered, saved_digest = 0, ""
            try:
                with _private_file(part, create=False) as file, _private_file(metadata, create=False) as record:
                    saved_digest = record.read(65).decode("ascii", errors="replace")
                    offered = os.fstat(file.fileno()).st_size
            except FileNotFoundError:
                pass
            if not offered or offered > MAX_FILE or not valid_digest(saved_digest):
                offered, saved_digest = 0, ""
            begin = self._control(GET_BEGIN, {
                "name": name, "offset": offered, "sha256": saved_digest,
            })
            size, sha256, offset = begin.get("size"), begin.get("sha256"), begin.get("offset")
            if (
                not _bounded_int(size, 0, MAX_FILE)
                or not valid_digest(sha256)
                or not _bounded_int(offset, 0, size)
                or (offset and (offset != offered or saved_digest != sha256))
            ):
                raise ProtocolError("GET_BEGIN 返回的文件元数据无效")

            with _private_file(part) as file, _private_file(metadata) as record:
                digest = hashlib.sha256()
                if offset:
                    if os.fstat(file.fileno()).st_size != offset:
                        raise ValueError("下载暂存文件在传输中发生变化")
                    remaining = offset
                    while remaining:
                        data = file.read(min(CHUNK, remaining))
                        if not data:
                            raise ValueError("下载暂存文件在传输中发生变化")
                        digest.update(data)
                        remaining -= len(data)
                else:
                    file.truncate(0)
                    file.flush()
                    os.fsync(file.fileno())
                    record.seek(0)
                    record.truncate(0)
                    record.write(sha256.encode("ascii"))
                    record.flush()
                    os.fsync(record.fileno())

                done = offset
                if progress:
                    progress(done, size)
                while done < size:
                    data = self._exchange(GET_CHUNK, encode_json({}), DATA)
                    if not 0 < len(data) <= min(CHUNK, size - done):
                        raise ProtocolError("GET_CHUNK 返回了超出剩余长度的数据或空数据")
                    file.write(data)
                    digest.update(data)
                    done += len(data)
                    if progress:
                        progress(done, size)
                valid = digest.hexdigest() == sha256
                if valid:
                    file.flush()
                    os.fsync(file.fileno())
            if not valid:
                part.unlink()
                metadata.unlink()
                raise ProtocolError("下载文件的 SHA-256 与服务器声明不匹配")
            os.replace(part, target)
            metadata.unlink()
            self._control(GET_END, {"sha256": sha256})
        return {"size": size, "sha256": sha256, "offset": offset}

    def close(self):
        with self._lock:
            if self.connected:
                try:
                    self._control(BYE)
                except (ProtocolError, RemoteError, OSError, EOFError):
                    pass
                finally:
                    self._abort()
        self._heartbeat.join()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.close()


def connection_args(description):
    parser = argparse.ArgumentParser(description=description)
    parser.add_argument("--state", required=True, type=Path, help="部署脚本生成的状态目录")
    parser.add_argument("--user", required=True, help="证书对应的用户 ID")
    parser.add_argument("--host", default="127.0.0.1", help="服务器证书中的主机名或 IP")
    parser.add_argument("--port", default=9443, type=int, help="服务器 TCP 端口")
    return parser.parse_args()


def main():
    args = connection_args("SFT/1 安全文件传输客户端")
    help_text = "list | put 本地路径 [远程名] | get 远程名 本地路径 | ping | quit"
    try:
        with Client(**vars(args)) as client:
            print(f"已连接 {client.info['user']} · {client.tls_version} · 本地端口 {client.local_address[1]}")
            print(help_text)
            while client.connected:
                try:
                    cmd = shlex.split(input("sft> "))
                except EOFError:
                    break
                except ValueError as exc:
                    print(f"命令格式错误 {exc}")
                    continue
                if not cmd:
                    continue
                action, *params = cmd
                try:
                    if action == "quit" and not params:
                        break
                    if action == "list" and not params:
                        files = client.list_files()
                        for item in files:
                            print(f"{item['size']:>10} B  {item['name']}")
                        print(f"共 {len(files)} 个文件")
                    elif action == "ping" and not params:
                        client.ping()
                        print(f"PONG · 本地端口 {client.local_address[1]}")
                    elif action == "put" and 1 <= len(params) <= 2:
                        receipt = client.upload(*params)
                        print(f"上传成功 {receipt['size']} B · 起始偏移 {receipt['offset']} B")
                        print(f"SHA-256 {receipt['sha256']}")
                    elif action == "get" and len(params) == 2:
                        receipt = client.download(*params)
                        print(f"下载成功 {receipt['size']} B · 起始偏移 {receipt['offset']} B")
                        print(f"SHA-256 {receipt['sha256']}")
                    else:
                        print(help_text)
                except (OSError, EOFError, ValueError, RemoteError, ProtocolError) as exc:
                    print(f"操作失败 {exc}")
    except (OSError, EOFError, ValueError, ProtocolError, RemoteError) as exc:
        raise SystemExit(f"连接失败 {exc}") from exc
    except KeyboardInterrupt:
        print()


if __name__ == "__main__":
    main()
