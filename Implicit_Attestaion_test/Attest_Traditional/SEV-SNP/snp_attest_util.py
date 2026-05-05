import os, subprocess, tempfile, json, socket, struct
import hashlib
import ctypes
import fcntl

def _looks_like_ascii_hex(buf: bytes) -> bool:
    # If buf is raw bytes it will usually contain lots of non-hex chars and zeros.
    # If it's ASCII-hex, it will be only [0-9a-f] and length is often 64/128.
    if len(buf) not in (64, 128):
        return False
    hexchars = b"0123456789abcdefABCDEF"
    return all(c in hexchars for c in buf)

def gen_report_bytes_bound_to_nonce(use_platform: bool = False, vmpl: int = 1) -> bytes:

    with tempfile.TemporaryDirectory(prefix="snpguest_") as td:
        req_path = os.path.join(td, "req.bin")
        rep_path = os.path.join(td, "report.bin")

        cmd = ["snpguest", "report", rep_path, req_path, "--vmpl", str(vmpl)]
        if use_platform:
            cmd.append("--platform")

        p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        if p.returncode != 0:
            raise RuntimeError(p.stdout.decode("utf-8", "ignore"))

        return open(rep_path, "rb").read()

def nonce_to_report_data64(nonce: bytes) -> bytes:
    if len(nonce) != 32:
        raise ValueError("nonce must be 32 bytes")
    h = hashlib.sha256(nonce).digest()          # 32 bytes
    return h + (b"\x00" * 32)                   # 64 bytes total

def nonce_to_report_data_hex(nonce: bytes) -> str:
    # 64 bytes -> 128 hex chars
    return nonce_to_report_data64(nonce).hex()



def _recvn(s, n):
    b = b""
    while len(b) < n:
        x = s.recv(n - len(b))
        if not x:
            raise RuntimeError("socket closed")
        b += x
    return b

def verify_report_via_tcp(verifier_host: str, verifier_port: int, report: bytes,
                          expected_measurement_hex: str | None,
                          expected_report_data_hex: str | None,
                          endorser: str = "vcek") -> dict:
    req = {
        "measurement": expected_measurement_hex,
        "report_data": expected_report_data_hex,
        "endorser": endorser,
    }
    j = json.dumps(req).encode("utf-8")

    with socket.create_connection((verifier_host, verifier_port), timeout=10) as s:
        s.sendall(struct.pack("!I", len(j)) + j)
        s.sendall(struct.pack("!I", len(report)) + report)

        _wire_rc = struct.unpack("!I", _recvn(s, 4))[0]
        jlen = struct.unpack("!I", _recvn(s, 4))[0]
        payload = _recvn(s, jlen) if jlen else b"{}"
        out = json.loads(payload.decode("utf-8"))
        out["rc_wire"] = int(_wire_rc)
        return out


# ============================================================
# In-process /dev/sev-guest ioctl path (alternative to snpguest report)
# ============================================================

_SNP_IOC_TYPE = ord('S')

class _SnpGuestRequestIoctl(ctypes.Structure):
    _pack_ = 1
    _fields_ = [
        ("msg_version", ctypes.c_uint8),
        ("_pad", ctypes.c_uint8 * 7),
        ("req_data", ctypes.c_uint64),
        ("resp_data", ctypes.c_uint64),
        ("exitinfo2", ctypes.c_uint64),
    ]

class _SnpReportReq(ctypes.Structure):
    _pack_ = 1
    _fields_ = [
        ("user_data", ctypes.c_uint8 * 64),
        ("vmpl", ctypes.c_uint32),
        ("rsvd", ctypes.c_uint8 * 28),
    ]

class _SnpReportResp(ctypes.Structure):
    _pack_ = 1
    _fields_ = [("data", ctypes.c_uint8 * 4000)]

_IOC_READ = 2
_IOC_WRITE = 1
def _ioc(d, t, nr, size):
    return (d << 30) | (size << 16) | (t << 8) | nr

SNP_GET_REPORT = _ioc(_IOC_READ | _IOC_WRITE, _SNP_IOC_TYPE, 0x0,
                       ctypes.sizeof(_SnpGuestRequestIoctl))

# Per AMD SEV-SNP firmware ABI: response has [status(4) + report_size(4)
# + reserved(24) + report(1184)] = 1216 bytes used out of 4000.
_REPORT_OFFSET = 32
_REPORT_SIZE = 1184


def gen_report_bytes_via_ioctl(use_platform: bool = True, vmpl: int = 1,
                                user_data: bytes = None) -> bytes:
    """
    Drop-in replacement for gen_report_bytes_bound_to_nonce — same return shape
    (raw 1184-byte SNP attestation report). Uses /dev/sev-guest ioctl directly,
    no snpguest subprocess.

    use_platform: accepted for signature compat; not used here.
    vmpl:        guest VMPL to bake into the report (default 1).
    user_data:   64-byte report_data field. None = zeros.

    NOTE: This bypasses snpguest entirely. Validate output matches
    `snpguest report` on your kernel/firmware version before relying on it.
    """
    if user_data is None:
        user_data = b"\x00" * 64
    if len(user_data) != 64:
        raise ValueError("user_data must be exactly 64 bytes")

    fd = os.open("/dev/sev-guest", os.O_RDWR)
    try:
        req = _SnpReportReq()
        ctypes.memmove(req.user_data, user_data, 64)
        req.vmpl = vmpl

        resp = _SnpReportResp()

        arg = _SnpGuestRequestIoctl()
        arg.msg_version = 1
        arg.req_data = ctypes.addressof(req)
        arg.resp_data = ctypes.addressof(resp)

        fcntl.ioctl(fd, SNP_GET_REPORT, arg, True)

        if arg.exitinfo2 != 0:
            fw = arg.exitinfo2 & 0xFFFFFFFF
            vmm = (arg.exitinfo2 >> 32) & 0xFFFFFFFF
            raise RuntimeError(
                f"SNP_GET_REPORT failed: fw_error={fw:#x} vmm_error={vmm:#x}"
            )

        return bytes(resp.data[_REPORT_OFFSET:_REPORT_OFFSET + _REPORT_SIZE])
    finally:
        os.close(fd)