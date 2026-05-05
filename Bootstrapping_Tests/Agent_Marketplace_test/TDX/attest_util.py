import os
import ctypes
import ctypes.util
import json
import socket
import struct

TDX_TEE_TYPE = 0x00000081

# tdx_report_data_t: 64 bytes
class _TdxReportData(ctypes.Structure):
    _fields_ = [("d", ctypes.c_uint8 * 64)]

# tdx_uuid_t: 16 bytes
class _TdxUuid(ctypes.Structure):
    _fields_ = [("d", ctypes.c_uint8 * 16)]

_lib = None

def _ensure_lib_loaded():
    global _lib
    if _lib is not None:
        return
    candidates = [
        "/usr/lib/x86_64-linux-gnu/libtdx_attest.so",
        "/usr/lib/x86_64-linux-gnu/libtdx_attest.so.1",
        "/usr/lib64/libtdx_attest.so",
    ]
    path = next((p for p in candidates if os.path.exists(p)), None)
    if path is None:
        path = ctypes.util.find_library("tdx_attest")
    if not path:
        raise RuntimeError(
            "libtdx_attest.so not found. Install Intel DCAP TDX attestation "
            "runtime (e.g. `apt install libtdx-attest`)."
        )
    lib = ctypes.CDLL(path)

    lib.tdx_att_get_quote.argtypes = [
        ctypes.POINTER(_TdxReportData),
        ctypes.POINTER(_TdxUuid),
        ctypes.c_uint32,
        ctypes.POINTER(_TdxUuid),
        ctypes.POINTER(ctypes.POINTER(ctypes.c_uint8)),
        ctypes.POINTER(ctypes.c_uint32),
        ctypes.c_uint32,
    ]
    lib.tdx_att_get_quote.restype = ctypes.c_int

    lib.tdx_att_free_quote.argtypes = [ctypes.POINTER(ctypes.c_uint8)]
    lib.tdx_att_free_quote.restype = ctypes.c_int

    _lib = lib


def gen_tdx_quote_bytes(config_path: str = "") -> bytes:
    """
    Generate a TDX quote in-process via libtdx_attest. The config_path arg is
    ignored (kept for compatibility with the previous trustauthority-cli version).
    report_data is set to a fixed 64-byte test value; in a real protocol this
    would be a hash of a peer-supplied challenge, but the benchmark only cares
    about timing and report_data contents don't affect quote-gen latency.
    """
    _ensure_lib_loaded()

    report_data = b"hetsec-tdx-attest-benchmark".ljust(64, b"\x00")

    rd = _TdxReportData()
    ctypes.memmove(rd.d, report_data, 64)

    pp_quote = ctypes.POINTER(ctypes.c_uint8)()
    quote_size = ctypes.c_uint32(0)

    rc = _lib.tdx_att_get_quote(
        ctypes.byref(rd),
        None, 0, None,
        ctypes.byref(pp_quote),
        ctypes.byref(quote_size),
        0,
    )
    if rc != 0:
        raise RuntimeError(f"tdx_att_get_quote failed: rc={rc:#x}")

    try:
        return bytes(ctypes.string_at(pp_quote, quote_size.value))
    finally:
        _lib.tdx_att_free_quote(pp_quote)


def _recvn(s, n):
    b = b""
    while len(b) < n:
        x = s.recv(n - len(b))
        if not x:
            raise RuntimeError("socket closed")
        b += x
    return b


def verify_quote_tcp(host: str, port: int, quote: bytes) -> dict:
    """
    Send raw quote bytes to the local QvE verifier daemon over TCP and return its JSON.
    Protocol: [u32 len_be][quote bytes] -> [u32 rc_be][u32 json_len_be][json bytes]
    """
    with socket.create_connection((host, port), timeout=5) as s:
        s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        s.sendall(struct.pack("!I", len(quote)) + quote)
        rc = struct.unpack("!I", _recvn(s, 4))[0]
        jlen = struct.unpack("!I", _recvn(s, 4))[0]
        payload = _recvn(s, jlen) if jlen else b"{}"
    out = json.loads(payload.decode("utf-8"))
    out["rc_wire"] = int(rc)
    return out
