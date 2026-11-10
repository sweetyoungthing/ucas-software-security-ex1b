"""EX1B v1 framing shared by the TLS endpoints."""

from dataclasses import dataclass
import json
import re
import socket
import struct
import time
import unicodedata


MAGIC = b"SFT1"
VERSION = 1
HEADER = struct.Struct("!4sBBHII")
HELLO, PING, LIST, PUT_BEGIN, PUT_CHUNK, PUT_END = range(1, 7)
GET_BEGIN, GET_CHUNK, GET_END, BYE = range(7, 11)
OK, DATA, ERROR = 128, 129, 255
CHUNK = 64 * 1024
MAX_JSON = 32 * 1024
MAX_FILE = 64 * 1024 * 1024
FRAME_TIMEOUT = 12
_OPERATIONS = {*range(HELLO, BYE + 1), OK, DATA, ERROR}
_BINARY = {PUT_CHUNK, DATA}
_DIGEST = re.compile(r"[0-9a-f]{64}")
_DEVICE = re.compile(r"CON|PRN|AUX|NUL|COM[0-9¹²³]|LPT[0-9¹²³]", re.I)


class ProtocolError(ValueError):
    """The peer sent an invalid frame."""


@dataclass(frozen=True)
class Frame:
    op: int
    rid: int
    payload: bytes


def _validate(op, rid, size):
    if op not in _OPERATIONS or not 1 <= rid <= 0xFFFFFFFF:
        raise ProtocolError("invalid operation or request ID")
    limit = CHUNK if op in _BINARY else MAX_JSON
    if not 1 <= size <= limit:
        raise ProtocolError("invalid frame length")


def _read_exact(sock, size, deadline):
    result = bytearray(size)
    remaining = memoryview(result)
    while remaining:
        seconds = deadline - time.monotonic()
        if seconds <= 0:
            raise TimeoutError("frame deadline exceeded")
        sock.settimeout(seconds)
        read = sock.recv_into(remaining)
        if not read:
            raise EOFError("peer closed the connection")
        remaining = remaining[read:]
    return bytes(result)


def recv_frame(sock, timeout=FRAME_TIMEOUT):
    """Bound allocation before reading the body and use one deadline per frame."""
    original_timeout = sock.gettimeout()
    deadline = time.monotonic() + timeout
    try:
        magic, version, op, flags, rid, size = HEADER.unpack(
            _read_exact(sock, HEADER.size, deadline)
        )
        if (magic, version, flags) != (MAGIC, VERSION, 0):
            raise ProtocolError("invalid magic, version or flags")
        _validate(op, rid, size)
        return Frame(op, rid, _read_exact(sock, size, deadline))
    finally:
        sock.settimeout(original_timeout)


def send_frame(sock, op, rid, payload=b""):
    _validate(op, rid, len(payload))
    original_timeout = sock.gettimeout()
    sock.settimeout(FRAME_TIMEOUT)
    try:
        sock.sendall(HEADER.pack(MAGIC, VERSION, op, 0, rid, len(payload)) + payload)
    finally:
        sock.settimeout(original_timeout)


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ProtocolError("duplicate JSON key")
        result[key] = value
    return result


def _invalid_constant(value):
    raise ProtocolError(f"invalid JSON constant: {value}")


def encode_json(value):
    if not isinstance(value, dict):
        raise ProtocolError("control payload must be a JSON object")
    return json.dumps(
        value, ensure_ascii=False, separators=(",", ":"), allow_nan=False
    ).encode("utf-8")


def decode_json(payload):
    try:
        value = json.loads(
            payload.decode("utf-8"),
            object_pairs_hook=_unique_object,
            parse_constant=_invalid_constant,
        )
    except (ValueError, RecursionError) as error:
        raise ProtocolError("invalid JSON control payload") from error
    if not isinstance(value, dict):
        raise ProtocolError("control payload must be a JSON object")
    return value


def valid_name(name):
    if not isinstance(name, str) or not name or name != unicodedata.normalize("NFC", name):
        return False
    if name[0] == "." or name[-1] in ". " or any(char in '/\\:*?"<>|' for char in name):
        return False
    if any(unicodedata.category(char).startswith("C") for char in name):
        return False
    return len(name.encode("utf-8")) <= 160 and not _DEVICE.fullmatch(
        name.partition(".")[0].rstrip()
    )


def valid_digest(value):
    return isinstance(value, str) and _DIGEST.fullmatch(value) is not None


def keepalive(sock):
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
