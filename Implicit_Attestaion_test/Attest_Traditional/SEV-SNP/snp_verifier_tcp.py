#!/usr/bin/env python3
"""In-process SEV-SNP attestation report verifier."""

import json
import os
import socket
import struct
import threading
import urllib.request

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

KDS_BASE = "https://kdsintf.amd.com"
DEFAULT_PROCESSOR_MODEL = os.environ.get("SNP_PROCESSOR_MODEL", "Milan")

# CA chain cache — static across deployment, realistic to cache.
_ca_cache: dict = {}
_ca_lock = threading.Lock()


# --- SNP report parser (1184 bytes) ----
# Signed body = bytes 0..672. Signature = bytes 672..1184 (72 LE r + 72 LE s).
_SIGNED_BODY_LEN = 0x2A0


def parse_report(data: bytes) -> dict:
    if len(data) < 1184:
        raise ValueError(f"report too short: {len(data)} bytes")
    return {
        "report_data":  data[80:144],
        "measurement":  data[144:192],
        "reported_tcb": struct.unpack_from("<Q", data, 384)[0],
        "chip_id":      data[416:480],
        "signed_body":  data[:_SIGNED_BODY_LEN],
        "sig_r_le":     data[672:672 + 72],
        "sig_s_le":     data[744:744 + 72],
    }


def tcb_to_query(tcb: int) -> dict:
    return {
        "blSPL":    (tcb >>  0) & 0xFF,
        "teeSPL":   (tcb >>  8) & 0xFF,
        "snpSPL":   (tcb >> 48) & 0xFF,
        "ucodeSPL": (tcb >> 56) & 0xFF,
    }


# --- KDS fetchers ----

def fetch_ca_chain(pm: str):
    with _ca_lock:
        if pm in _ca_cache:
            return _ca_cache[pm]
    url = f"{KDS_BASE}/vcek/v1/{pm}/cert_chain"
    with urllib.request.urlopen(url, timeout=30) as r:
        chain_pem = r.read()
    certs = x509.load_pem_x509_certificates(chain_pem)
    if len(certs) < 2:
        raise RuntimeError(f"unexpected CA chain length: {len(certs)}")
    ask, ark = certs[0], certs[1]
    with _ca_lock:
        _ca_cache[pm] = (ark, ask)
    return ark, ask


def fetch_vcek(pm: str, chip_id: bytes, tcb: int) -> x509.Certificate:
    q = tcb_to_query(tcb)
    url = (f"{KDS_BASE}/vcek/v1/{pm}/{chip_id.hex()}"
           f"?blSPL={q['blSPL']}&teeSPL={q['teeSPL']}"
           f"&snpSPL={q['snpSPL']}&ucodeSPL={q['ucodeSPL']}")
    with urllib.request.urlopen(url, timeout=30) as r:
        return x509.load_der_x509_certificate(r.read())


# --- Signature verification ----

def _verify_cert_signed_by(child: x509.Certificate, parent: x509.Certificate):
    pub = parent.public_key()
    sig = child.signature
    tbs = child.tbs_certificate_bytes
    halg = child.signature_hash_algorithm
    if isinstance(pub, rsa.RSAPublicKey):
        pub.verify(sig, tbs, padding.PKCS1v15(), halg)
    elif isinstance(pub, ec.EllipticCurvePublicKey):
        pub.verify(sig, tbs, ec.ECDSA(halg))
    else:
        raise RuntimeError(f"unsupported key type: {type(pub).__name__}")


def verify_chain(vcek, ask, ark):
    _verify_cert_signed_by(vcek, ask)
    _verify_cert_signed_by(ask, ark)
    _verify_cert_signed_by(ark, ark)


def verify_report_signature(fields: dict, vcek: x509.Certificate):
    # SNP signature is two 72-byte LE numbers; first 48 bytes used (P-384).
    r = int.from_bytes(fields["sig_r_le"][:48], "little")
    s = int.from_bytes(fields["sig_s_le"][:48], "little")
    der_sig = encode_dss_signature(r, s)
    vcek.public_key().verify(der_sig, fields["signed_body"], ec.ECDSA(hashes.SHA384()))


def verify_snp_report(report_bytes: bytes,
                      expected_measurement_hex,
                      expected_report_data_hex,
                      endorser: str = "vcek",
                      processor_model: str = None) -> dict:
    if endorser != "vcek":
        return {"ok": False, "stage": "unsupported_endorser", "rc": 1,
                "out": f"only vcek supported; got {endorser}"}
    pm = processor_model or DEFAULT_PROCESSOR_MODEL

    try:
        f = parse_report(report_bytes)
    except Exception as e:
        return {"ok": False, "stage": "parse_report", "rc": 1, "out": str(e)}

    if expected_measurement_hex:
        em = expected_measurement_hex.lower().lstrip("0x")
        if f["measurement"].hex() != em:
            return {"ok": False, "stage": "verify_measurement", "rc": 1,
                    "out": f"measurement mismatch: got {f['measurement'].hex()} expected {em}"}
    if expected_report_data_hex:
        ed = expected_report_data_hex.lower().lstrip("0x")
        if f["report_data"].hex() != ed:
            return {"ok": False, "stage": "verify_report_data", "rc": 1,
                    "out": f"report_data mismatch: got {f['report_data'].hex()} expected {ed}"}

    try:
        ark, ask = fetch_ca_chain(pm)
    except Exception as e:
        return {"ok": False, "stage": "fetch_ca", "rc": 1, "out": str(e)}
    try:
        vcek = fetch_vcek(pm, f["chip_id"], f["reported_tcb"])
    except Exception as e:
        return {"ok": False, "stage": "fetch_vcek", "rc": 1, "out": str(e)}
    try:
        verify_chain(vcek, ask, ark)
    except InvalidSignature as e:
        return {"ok": False, "stage": "verify_certs", "rc": 1, "out": str(e)}
    try:
        verify_report_signature(f, vcek)
    except InvalidSignature as e:
        return {"ok": False, "stage": "verify_attestation", "rc": 1, "out": str(e)}

    return {"ok": True, "stage": "ok", "rc": 0, "out": ""}


# --- TCP server (wire protocol unchanged) ----

def _recvn(sock, n):
    b = b""
    while len(b) < n:
        x = sock.recv(n - len(b))
        if not x:
            raise ConnectionError("socket closed")
        b += x
    return b


def handle_conn(c):
    jlen = struct.unpack("!I", _recvn(c, 4))[0]
    j = json.loads(_recvn(c, jlen).decode("utf-8")) if jlen else {}
    rlen = struct.unpack("!I", _recvn(c, 4))[0]
    report = _recvn(c, rlen)
    result = verify_snp_report(
        report,
        j.get("measurement"),
        j.get("report_data"),
        endorser=j.get("endorser", "vcek"),
    )
    payload = json.dumps(result).encode("utf-8")
    rc = 0 if result.get("ok") else 1
    c.sendall(struct.pack("!I", rc) + struct.pack("!I", len(payload)) + payload)


def main():
    host, port = "0.0.0.0", 7777
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((host, port))
    s.listen(64)
    print(f"SNP verifier (in-process) listening on {host}:{port}; processor_model={DEFAULT_PROCESSOR_MODEL}")
    while True:
        c, _ = s.accept()
        try:
            handle_conn(c)
        except Exception as e:
            payload = json.dumps({"ok": False, "stage": "server_exception", "out": str(e)}).encode("utf-8")
            try:
                c.sendall(struct.pack("!I", 1) + struct.pack("!I", len(payload)) + payload)
            except Exception:
                pass
        finally:
            c.close()


if __name__ == "__main__":
    main()
