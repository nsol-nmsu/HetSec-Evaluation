import json
import socket
import struct
from cryptography import x509
from cryptography.x509.oid import ObjectIdentifier



GRAMINE_QUOTE_OID = ObjectIdentifier("0.6.9.42.840.113741.1337.6")

def extract_gramine_quote_from_cert_der(cert_der: bytes) -> bytes:
    """
    Extract Gramine quote bytes from a DER-encoded X.509 certificate.
    Raises cryptography.x509.ExtensionNotFound if the OID is absent.
    """
    cert = x509.load_der_x509_certificate(cert_der)
    ext = cert.extensions.get_extension_for_oid(GRAMINE_QUOTE_OID)
    # cryptography returns an UnrecognizedExtension; .value.value is the raw extension payload bytes
    return ext.value.value

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

def verify_peer_cert_via_qve(peer_cert_der: bytes, qve_host: str = "127.0.0.1", qve_port: int = 7777) -> dict:
    """
    Convenience: cert DER -> quote -> verify via TCP QvE verifier.
    """
    quote = extract_gramine_quote_from_cert_der(peer_cert_der)
    return verify_quote_tcp(qve_host, qve_port, quote)