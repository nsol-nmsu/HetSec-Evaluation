import os
import time
import socket
import queue
import asyncio
import ssl
from attest_util_async import verify_peer_cert_via_qve

total = 0
async def read_framed(reader):
    chunks = await reader.readline()
    if not chunks:
        return b""
    chunks = int(chunks[:-1])
    data = b""
    for _ in range(chunks):
        data += await reader.read(1024)
    return data

def chunks_for_len(n: int) -> bytes:
    chunks = (n + 1023) // 1024
    return (str(chunks).encode() + b"\n")

async def write_framed(writer, blob: bytes):
    writer.write(chunks_for_len(len(blob)))
    await writer.drain()
    writer.write(blob)
    await writer.drain()

async def handle_client(reader, writer):
    global t_0
    global total

    if total == 0:
        t_0 = time.perf_counter()

    request = await read_framed(reader)

    response = None
    if request[0:20] == b'Coordinator_Attest_2':
        if not request[20:]:
            writer.close()
            await writer.wait_closed()
            return
        try:
            ver = await verify_peer_cert_via_qve(request[20:], "127.0.0.1", 7777)
        except Exception as e:
            print(f"Client attestation exception: {e}")
            writer.close()
            await writer.wait_closed()
            return

        # QvE convention: rc_wire 0 or 1 == success, anything else is failure
        if int(ver.get("rc_wire", -1)) not in (0, 1):
            writer.close()
            await writer.wait_closed()
            return

        with open("userInfo.json", 'rb') as file:
            response = file.read()

    await write_framed(writer, response)
    await writer.drain()
    t_resp = time.perf_counter()

    writer.close()
    await writer.wait_closed()

    if request[0:20] == b'Coordinator_Attest_2':
        total += 1
        if total == 10000:
            print(f"{t_resp - t_0}, {total}")
            total = 0


async def main():
    ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ssl_context.load_cert_chain('server.crt', 'server.key')
    ssl_context.check_hostname = False
    ssl_context.verify_mode = ssl.CERT_NONE

    host = "0.0.0.0"
    port = 5007
    server = await asyncio.start_server(
        handle_client, host, port, ssl=ssl_context, family=socket.AF_INET
    )
    addrs = ', '.join(str(sock.getsockname()) for sock in server.sockets)
    print(f"Serving on {addrs}")


    async with server:
        await server.serve_forever()


if __name__ == '__main__':
    asyncio.run(main())
