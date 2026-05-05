import json
import socket
import struct
import asyncio


async def _recvn(reader, n):
    return await reader.readexactly(n)


async def verify_quote_tcp(host: str, port: int, quote: bytes) -> dict:
    """
    Send a raw TDX quote to the local QvE verifier daemon over TCP and return its JSON.
    Protocol: [u32 len_be][quote bytes] -> [u32 rc_be][u32 json_len_be][json bytes]

    QvE itself runs on SGX hardware (it's an SGX enclave) but verifies both
    SGX and TDX quotes. The wire protocol is identical for both.
    """
    reader, writer = await asyncio.wait_for(
        asyncio.open_connection(host=host, port=port, family=socket.AF_INET),
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
        if hasattr(writer, "wait_closed"):
            try:
                await writer.wait_closed()
            except Exception:
                pass

    out = json.loads(payload.decode("utf-8"))
    out["rc_wire"] = int(rc)
    return out


async def verify_peer_cert_via_qve(quote_bytes: bytes,
                                    qve_host: str = "127.0.0.1",
                                    qve_port: int = 7777) -> dict:
    """
    Compatibility shim. The name matches the SGX/Gramine helper used by the
    other platforms' bootstrap servers, but for TDX it sends the raw quote
    directly to QvE — no Gramine OID/cert extraction needed since TDX clients
    transmit raw quote bytes.
    """
    return await verify_quote_tcp(qve_host, qve_port, quote_bytes)
