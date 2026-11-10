"""Secure Transfer Lab server. Requires POSIX directory-relative file access."""

import argparse
from contextlib import suppress
from dataclasses import dataclass
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import socket
import ssl
import stat
import threading
import time
from typing import BinaryIO
import unicodedata

from protocol import (
    BYE, CHUNK, DATA, ERROR, GET_BEGIN, GET_CHUNK, GET_END, HELLO, LIST,
    FRAME_TIMEOUT, MAX_FILE, OK, PING, PUT_BEGIN, PUT_CHUNK, PUT_END, ProtocolError,
    decode_json, encode_json, keepalive, recv_frame, send_frame,
    valid_digest, valid_name,
)

MAX_CONNECTIONS = 12
MAX_USER_SESSIONS = 4
HANDSHAKE_TIMEOUT = 4
DISK_QUOTA = 256 * 1024 * 1024
MAX_ENTRIES = 128
MIN_RATE = 256 * 1024
MAX_RATE = 64 * 1024 * 1024
DIR_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
USER_NAME = re.compile(r"[a-z][a-z0-9_-]{0,31}")


class Rejected(Exception):
    """An application request that can receive an ERROR response."""


def private_directory(path, parent=None):
    fd = os.open(path, DIR_FLAGS, dir_fd=parent)
    info = os.fstat(fd)
    if info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700:
        os.close(fd)
        raise ValueError(f"{path}: must be owned by the service account with mode 0700")
    return fd


def is_regular(info):
    return stat.S_ISREG(info.st_mode) and info.st_nlink == 1


def open_regular(directory, name, flags, mode):
    fd = os.open(name, flags | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600, dir_fd=directory)
    if not is_regular(os.fstat(fd)):
        os.close(fd)
        raise Rejected("only regular files with one link are permitted")
    return os.fdopen(fd, mode, buffering=0)


def file_digest(file):
    file.seek(0)
    digest = hashlib.sha256()
    while block := file.read(CHUNK):
        digest.update(block)
    return digest.hexdigest()


def check_name(name):
    if not valid_name(name):
        raise Rejected("invalid filename")


@dataclass
class Upload:
    file: BinaryIO
    name: str
    key: str
    part: str
    size: int
    digest: str


@dataclass
class Download:
    file: BinaryIO
    size: int
    digest: str


class Account:
    def __init__(self, name, rate, directory):
        self.name = name
        self.rate = rate
        self.directory = directory
        self.lock = threading.Lock()
        self.bandwidth_lock = threading.Lock()
        self.next_data_time = 0.0
        self.sessions = threading.BoundedSemaphore(MAX_USER_SESSIONS)
        self.active_names = set()
        self.reserved = {}

    def pace(self, count):
        # Schedule bytes from all TLS sessions of this user on one timeline.
        with self.bandwidth_lock:
            now = time.monotonic()
            finish = max(self.next_data_time, now) + count / self.rate
            self.next_data_time = finish
        time.sleep(max(0, finish - time.monotonic()))

    def list_files(self):
        files = []
        with self.lock:
            for name in os.listdir(self.directory):
                if not valid_name(name):
                    continue
                info = os.stat(name, dir_fd=self.directory, follow_symlinks=False)
                if is_regular(info) and info.st_size <= MAX_FILE:
                    files.append({"name": name, "size": info.st_size})
        return sorted(files, key=lambda entry: entry["name"])

    def start_upload(self, name, size, digest):
        # Case/normalization aliases can identify one target on a macOS volume.
        key = unicodedata.normalize("NFC", name.casefold())
        identity = json.dumps([name, size, digest], ensure_ascii=False).encode("utf-8")
        part = ".part-" + hashlib.sha256(identity).hexdigest()
        with self.lock:
            if key in self.active_names:
                raise Rejected("another upload owns this filename")
            try:
                target = os.stat(name, dir_fd=self.directory, follow_symlinks=False)
            except FileNotFoundError:
                pass
            else:
                if not is_regular(target):
                    raise Rejected("upload destination is not a regular file")

            entries = os.listdir(self.directory)
            if part not in entries and len(entries) >= MAX_ENTRIES:
                raise Rejected("per-user file entry limit reached")
            occupied = 0
            for entry in entries:
                if entry == part:
                    continue
                info = os.stat(entry, dir_fd=self.directory, follow_symlinks=False)
                if stat.S_ISREG(info.st_mode):
                    occupied += max(info.st_size, self.reserved.get(entry, 0))
            if occupied + size > DISK_QUOTA:
                raise Rejected("per-user disk quota exceeded")

            file = open_regular(self.directory, part, os.O_RDWR | os.O_CREAT, "r+b")
            if file.seek(0, os.SEEK_END) > size:
                file.close()
                raise Rejected("stored partial exceeds the declared size")
            self.active_names.add(key)
            self.reserved[part] = size
            return Upload(file, name, key, part, size, digest)

    def finish_upload(self, upload):
        os.fsync(upload.file.fileno())
        with self.lock:
            os.replace(
                upload.part, upload.name, src_dir_fd=self.directory, dst_dir_fd=self.directory
            )
            os.fsync(self.directory)

    def discard_upload(self, upload):
        with self.lock:
            os.unlink(upload.part, dir_fd=self.directory)

    def open_download(self, name):
        # Keep publication from unlinking the old inode between open and fstat.
        with self.lock:
            return open_regular(self.directory, name, os.O_RDONLY, "rb")

    def release_upload(self, upload):
        try:
            upload.file.close()
        finally:
            with self.lock:
                self.active_names.remove(upload.key)
                del self.reserved[upload.part]


class Session:
    def __init__(self, sock, account):
        self.sock = sock
        self.account = account
        self.greeted = False
        self.transfer = None
        self.handlers = {
            HELLO: (self.hello, ()),
            PING: (self.ping, ()),
            LIST: (self.list_files, ()),
            PUT_BEGIN: (self.put_begin, ("name", "size", "sha256")),
            PUT_CHUNK: (self.put_chunk, None),
            PUT_END: (self.put_end, ()),
            GET_BEGIN: (self.get_begin, ("name", "offset", "sha256")),
            GET_CHUNK: (self.get_chunk, ()),
            GET_END: (self.get_end, ("sha256",)),
            BYE: (self.ping, ()),
        }

    def reset(self):
        transfer, self.transfer = self.transfer, None
        if isinstance(transfer, Upload):
            self.account.release_upload(transfer)
        elif isinstance(transfer, Download):
            transfer.file.close()

    def run(self):
        try:
            while True:
                frame = recv_frame(self.sock, timeout=FRAME_TIMEOUT)
                try:
                    result = self.handle(frame)
                    if isinstance(result, bytes):
                        op, payload = DATA, result
                    else:
                        op, payload = OK, encode_json(result)
                except (Rejected, ProtocolError) as exc:
                    self.reset()
                    op, payload = ERROR, encode_json({"error": str(exc)})
                except FileNotFoundError:
                    self.reset()
                    op, payload = ERROR, encode_json({"error": "file not found"})
                except OSError as exc:
                    self.reset()
                    print(f"I/O error for {self.account.name}: {exc}", flush=True)
                    op, payload = ERROR, encode_json({"error": "file unavailable or storage I/O error"})
                send_frame(self.sock, op, frame.rid, payload)
                if frame.op == BYE and op == OK:
                    return
        finally:
            self.reset()

    def handle(self, frame):
        if not self.greeted and frame.op != HELLO:
            raise Rejected("HELLO required")
        if isinstance(self.transfer, Upload) and frame.op not in (PING, BYE, PUT_CHUNK, PUT_END):
            raise Rejected("an upload is in progress")
        if isinstance(self.transfer, Download) and frame.op not in (PING, BYE, GET_CHUNK, GET_END):
            raise Rejected("a download is in progress")
        if frame.op not in self.handlers:
            raise Rejected("unknown operation")
        handler, keys = self.handlers[frame.op]
        if keys is None:
            return handler(frame.payload)
        fields = decode_json(frame.payload)
        if fields.keys() != set(keys):
            raise Rejected("unexpected control fields")
        return handler(**fields)

    def hello(self):
        if self.greeted:
            raise Rejected("HELLO was already accepted")
        self.greeted = True
        return {"user": self.account.name, "rate": self.account.rate}

    def ping(self):
        return {}

    def list_files(self):
        return {"files": self.account.list_files()}

    def put_begin(self, name, size, sha256):
        check_name(name)
        if type(size) is not int or not 0 <= size <= MAX_FILE or not valid_digest(sha256):
            raise Rejected("invalid upload size or digest")
        self.transfer = self.account.start_upload(name, size, sha256)
        return {"offset": self.transfer.file.tell()}

    def put_chunk(self, payload):
        upload = self.transfer
        if not isinstance(upload, Upload):
            raise Rejected("PUT_BEGIN required")
        if not 0 < len(payload) <= CHUNK or upload.file.tell() + len(payload) > upload.size:
            raise Rejected("invalid upload chunk length")
        self.account.pace(len(payload))
        if upload.file.write(payload) != len(payload):
            raise OSError("short file write")
        return {"offset": upload.file.tell()}

    def put_end(self):
        upload = self.transfer
        if not isinstance(upload, Upload):
            raise Rejected("PUT_BEGIN required")
        if upload.file.tell() != upload.size:
            raise Rejected("upload is incomplete")
        if file_digest(upload.file) != upload.digest:
            self.account.discard_upload(upload)
            raise Rejected("upload SHA-256 mismatch")
        self.account.finish_upload(upload)
        result = {"size": upload.size, "sha256": upload.digest}
        self.reset()
        return result

    def get_begin(self, name, offset, sha256):
        check_name(name)
        if type(offset) is not int or not 0 <= offset <= MAX_FILE:
            raise Rejected("invalid download offset")
        if sha256 != "" and not valid_digest(sha256):
            raise Rejected("invalid download digest")
        file = self.account.open_download(name)
        try:
            size = os.fstat(file.fileno()).st_size
            if size > MAX_FILE:
                raise Rejected("file exceeds transfer limit")
            digest = file_digest(file)
            accepted = offset if sha256 == digest and offset <= size else 0
            file.seek(accepted)
            self.transfer = Download(file, size, digest)
        except BaseException:
            file.close()
            raise
        return {"size": size, "sha256": digest, "offset": accepted}

    def get_chunk(self):
        download = self.transfer
        if not isinstance(download, Download):
            raise Rejected("GET_BEGIN required")
        count = min(CHUNK, download.size - download.file.tell())
        if count <= 0:
            raise Rejected("all download bytes have been sent")
        payload = download.file.read(count)
        if len(payload) != count:
            raise OSError("download file changed while reading")
        self.account.pace(count)
        return payload

    def get_end(self, sha256):
        download = self.transfer
        if not isinstance(download, Download):
            raise Rejected("GET_BEGIN required")
        if download.file.tell() != download.size or sha256 != download.digest:
            raise Rejected("download size or SHA-256 was not confirmed")
        self.reset()
        return {}


def load_accounts(state, storage):
    users = json.loads((state / "server" / "users.json").read_text(encoding="utf-8"))
    if not isinstance(users, dict) or not users:
        raise ValueError("users.json must map client certificate fingerprints to accounts")
    names = {}
    fingerprints = {}
    for fingerprint, fields in users.items():
        if not valid_digest(fingerprint) or not isinstance(fields, dict):
            raise ValueError("invalid certificate fingerprint or account record")
        name, rate = fields.get("name"), fields.get("rate")
        if not isinstance(name, str) or not USER_NAME.fullmatch(name):
            raise ValueError("invalid account name")
        if type(rate) is not int or not MIN_RATE <= rate <= MAX_RATE:
            raise ValueError("invalid account bandwidth")
        if name not in names:
            names[name] = Account(name, rate, private_directory(name, storage))
        elif names[name].rate != rate:
            raise ValueError("inconsistent bandwidth for one account")
        fingerprints[fingerprint] = names[name]
    return fingerprints


def client_worker(raw, context, accounts, slots):
    try:
        with raw:
            raw.settimeout(HANDSHAKE_TIMEOUT)
            keepalive(raw)
            with context.wrap_socket(raw, server_side=True) as secure:
                fingerprint = hashlib.sha256(secure.getpeercert(binary_form=True)).hexdigest()
                account = accounts.get(fingerprint)
                if account is None or not account.sessions.acquire(blocking=False):
                    return
                try:
                    Session(secure, account).run()
                finally:
                    account.sessions.release()
    except (EOFError, ProtocolError, OSError):
        # Disconnected peers, handshake failures and bad framing release admission.
        pass
    finally:
        slots.release()


def serve(host, port, state):
    storage = private_directory(state / "storage")
    try:
        fcntl.flock(storage, fcntl.LOCK_EX | fcntl.LOCK_NB)
        accounts = load_accounts(state, storage)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_3
        context.verify_mode = ssl.CERT_REQUIRED
        context.load_verify_locations(cafile=str(state / "server" / "ca.pem"))
        context.load_cert_chain(state / "server" / "cert.pem", state / "server" / "key.pem")
        slots = threading.BoundedSemaphore(MAX_CONNECTIONS)
        family = socket.AF_INET6 if ":" in host else socket.AF_INET
        with socket.create_server((host, port), family=family, backlog=MAX_CONNECTIONS) as listener:
            print(f"READY {listener.getsockname()[1]}", flush=True)
            while True:
                raw, _ = listener.accept()
                if not slots.acquire(blocking=False):
                    raw.close()
                    continue
                try:
                    threading.Thread(
                        target=client_worker, args=(raw, context, accounts, slots), daemon=True
                    ).start()
                except RuntimeError:
                    raw.close()
                    slots.release()
                    raise
    finally:
        os.close(storage)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", default=9443, type=int)
    parser.add_argument("--state", type=Path, required=True)
    args = parser.parse_args()
    try:
        serve(args.host, args.port, args.state)
    except KeyboardInterrupt:
        pass
    except (OSError, ValueError) as exc:
        parser.exit(1, f"server: {exc}\n")


if __name__ == "__main__":
    main()
