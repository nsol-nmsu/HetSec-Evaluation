import os
import time
import socket
import queue
import asyncio
import ssl
from snp_attest_util import gen_report_bytes_bound_to_nonce, nonce_to_report_data_hex, verify_report_via_tcp

EXPECTED_CLIENT_MEASUREMENT = "0x6A063BE9DD79F6371C842E480F8DC3B5C725961344E57130E88C5ADF49E8F7F6C79B75A5EB77FC769959F4AEB2F9401E"

async def recv_exact(reader, n: int) -> bytes:
    b = b""
    while len(b) < n:
        chunk = await reader.read(n - len(b))
        if not chunk:
            raise ConnectionError("eof")
        b += chunk
    return b

async def send_frame(writer, blob: bytes):
    writer.write(len(blob).to_bytes(4, "big") + blob)
    await writer.drain()

async def recv_frame(reader) -> bytes:
    n = int.from_bytes(await recv_exact(reader, 4), "big")
    return await recv_exact(reader, n)

#handles what the clients sends, and formats it for the handle_client()
#handling of clients, what to send to them, what to do to them
async def handle_client(reader, writer):   
    t0 = time.perf_counter()

    t_gen0 = time.perf_counter()
    my_report = gen_report_bytes_bound_to_nonce(use_platform=True)
    t_gen1 = time.perf_counter()

    await send_frame(writer, my_report)
    t_send1 = time.perf_counter()

    response = await recv_frame(reader)
    t_recv_ok = time.perf_counter()
    if(response != b'Ok'):
        raise RuntimeError(f"attestation failed") 

    client_report = await recv_frame(reader)
    t_recv_rep = time.perf_counter()

    out = verify_report_via_tcp(
            "127.0.0.1", 7777,
            client_report,
            expected_measurement_hex=EXPECTED_CLIENT_MEASUREMENT,
            expected_report_data_hex=None,
            endorser="vcek",
        )
    t_ver = time.perf_counter()

    if not out.get("ok"):
        raise RuntimeError(f"client attestation failed: {out}")

    await send_frame(writer, b'Ok')
    t_send2 = time.perf_counter()

    print(
        "Server timings ms:",
        f"gen_report={(t_gen1-t_gen0)*1000:.2f}",
        f"send_server_report={(t_send1-t_gen1)*1000:.2f}",
        f"wait_client_ok={(t_recv_ok-t_send1)*1000:.2f}",
        f"wait_client_report={(t_recv_rep-t_recv_ok)*1000:.2f}",
        f"verify_client={(t_ver-t_recv_rep)*1000:.2f}",
        f"send_final_ok={(t_send2-t_ver)*1000:.2f}",
        f"total={(t_send2-t0)*1000:.2f}",
    )

    await writer.drain()
    writer.close()
    await writer.wait_closed()
    
        
async def main():
    ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ssl_context.load_cert_chain('server.crt', 'server.key')
    ssl_context.check_hostname = False
    ssl_context.verify_mode = ssl.CERT_NONE   # IMPORTANT: ask for client cert
    
    host = "127.0.0.1"
    #host = socket.gethostname()
    host = "0.0.0.0"

    port = 5007
    server = await asyncio.start_server(
        handle_client, host, port, ssl=ssl_context, family=socket.AF_INET
    )
    addrs = ', '.join(str(sock.getsockname()) for sock in server.sockets)
    print(f"Serving on {addrs}")

    async with server:
        await server.serve_forever()

#grpc 
if __name__ == '__main__':
    asyncio.run(main())


