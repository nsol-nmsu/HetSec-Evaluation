import os, subprocess, tempfile, json, socket, struct
import hashlib

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