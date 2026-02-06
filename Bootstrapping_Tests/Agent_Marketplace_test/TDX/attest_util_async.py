import json
import socket
import struct
from cryptography import x509
from cryptography.x509.oid import ObjectIdentifier
import asyncio


GRAMINE_QUOTE_OID = ObjectIdentifier("0.6.9.42.840.113741.1337.6")

async def extract_gramine_quote_from_cert_der(cert_der: bytes) -> bytes:
    """
    Extract Gramine quote bytes from a DER-encoded X.509 certificate.
    Raises cryptography.x509.ExtensionNotFound if the OID is absent.
    """
    cert = x509.load_der_x509_certificate(cert_der)
    ext = cert.extensions.get_extension_for_oid(GRAMINE_QUOTE_OID)
    # cryptography returns an UnrecognizedExtension; .value.value is the raw extension payload bytes
    return ext.value.value

async def _recvn(reader, n):
    return await reader.readexactly(n)

async def verify_quote_tcp(host: str, port: int, quote: bytes) -> dict:
    """
    Send raw quote bytes to the local QvE verifier daemon over TCP and return its JSON.
    Protocol: [u32 len_be][quote bytes] -> [u32 rc_be][u32 json_len_be][json bytes]
    """    
    reader, writer = await asyncio.wait_for(
        asyncio.open_connection( host=host, port=port, family=socket.AF_INET,),
        timeout=5,
    )
    try:
        sock = writer.get_extra_info("socket")
        if sock is not None:
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

        writer.write(struct.pack("!I", len(quote)) + quote)
        await asyncio.wait_for(writer.drain(), timeout=5)
        rc = struct.unpack("!I", await asyncio.wait_for(_recvn(reader, 4), timeout=5))[0]
        jlen = struct.unpack("!I", await asyncio.wait_for(_recvn(reader, 4), timeout=5))[0]
        payload = await asyncio.wait_for(_recvn(reader, jlen), timeout=5) if jlen else b"{}"

    finally:
        writer.close()
        # wait_closed exists on StreamWriter in modern Python; guard for older versions
        if hasattr(writer, "wait_closed"):
            try:
                await writer.wait_closed()
            except Exception:
                pass

    out = json.loads(payload.decode("utf-8"))
    out["rc_wire"] = int(rc)
    return out

async def verify_peer_cert_via_qve(peer_cert_der: bytes, qve_host: str = "127.0.0.1", qve_port: int = 7777) -> dict:
    """
    Convenience: cert DER -> quote -> verify via TCP QvE verifier.
    """
    quote = await extract_gramine_quote_from_cert_der(peer_cert_der)
    result = await verify_quote_tcp(qve_host, qve_port, quote)
    return result