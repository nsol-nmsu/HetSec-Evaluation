import os
import time
import socket
import queue
import asyncio
import ssl
from attest_util import verify_peer_cert_via_qve

recv_times = []
verify_times = []
send_ok_times = []
total_times = []

async def read_framed(reader):
    chunks = await reader.readline()
    if not chunks:
        return b""
    chunks = int(chunks[:-1])
    data = b""
    for _ in range(chunks):
        data += await reader.read(1024)
    return data



#handles what the clients sends, and formats it for the handle_client()
#handling of clients, what to send to them, what to do to them
async def handle_client(reader, writer):   

    t0 = time.perf_counter()
    client_cert_der = await read_framed(reader)
    t_recv  = time.perf_counter()

    if not client_cert_der:
        writer.close()
        await writer.wait_closed()
        return

    try:
        ver = verify_peer_cert_via_qve(client_cert_der, "127.0.0.1", 7777)
    except Exception as e:
        print(f"Client attestation exception: {e}")
        writer.close()
        await writer.wait_closed()
        return
        
    t_verify  = time.perf_counter()

    # Policy: accept rc 0 or rc 1, reject rc < 0
    if int(ver.get("rc", -1)) < 0:
        writer.close()
        await writer.wait_closed()
        return

    writer.write(b"OK\n")
    await writer.drain()
    t_ok = time.perf_counter()

    writer.close()
    await writer.wait_closed()

    print(
        f"{ (t_recv - t0)*1000:.2f}, { (t_verify - t_recv)*1000:.2f}, { (t_ok - t_verify)*1000:.2f}, { (t_ok - t0)*1000:.2f}"
    )    

    
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
    print( "recv,verify,send_ok,total")    

    async with server:
        await server.serve_forever()

#grpc 
if __name__ == '__main__':
    asyncio.run(main())


