import json
import socket
import struct
import asyncio


async def _recvn(reader, n):
    return await reader.readexactly(n)


async def verify_report_via_tcp(host: str, port: int, report: bytes,
                                 expected_measurement_hex=None,
                                 expected_report_data_hex=None,
                                 endorser: str = "vcek") -> dict:
    """
    Async equivalent of snp_attest_util.verify_report_via_tcp:
    sends a SEV-SNP attestation report to the in-process verifier daemon
    over TCP and returns its JSON response.

    Wire: [u32 jlen][json header][u32 rlen][report]
       -> [u32 rc][u32 plen][json result]
    """
    req = {
        "measurement": expected_measurement_hex,
        "report_data": expected_report_data_hex,
        "endorser": endorser,
    }
    j = json.dumps(req).encode("utf-8")

    reader, writer = await asyncio.wait_for(
        asyncio.open_connection(host=host, port=port, family=socket.AF_INET),
        timeout=10,
    )
    try:
        sock = writer.get_extra_info("socket")
        if sock is not None:
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

        writer.write(struct.pack("!I", len(j)) + j)
        writer.write(struct.pack("!I", len(report)) + report)
        await asyncio.wait_for(writer.drain(), timeout=30)

        rc = struct.unpack("!I", await asyncio.wait_for(_recvn(reader, 4), timeout=30))[0]
        plen = struct.unpack("!I", await asyncio.wait_for(_recvn(reader, 4), timeout=30))[0]
        payload = await asyncio.wait_for(_recvn(reader, plen), timeout=30) if plen else b"{}"
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


async def verify_peer_cert_via_qve(report_bytes: bytes,
                                    qve_host: str = "127.0.0.1",
                                    qve_port: int = 7777) -> dict:
    """
    Compatibility shim. The name matches the SGX/Gramine helper used by the
    other platforms' bootstrap servers, but for SEV-SNP it actually performs
    the SEV-SNP report verification protocol against the SNP verifier daemon.
    Lets the bootstrap server files import the same name across platforms.
    """
    return await verify_report_via_tcp(
        qve_host, qve_port, report_bytes,
        expected_measurement_hex=None,
        expected_report_data_hex=None,
        endorser="vcek",
    )
