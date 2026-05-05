import os
import time
import random
import socket
import json
import asyncio
import ssl 
import re
import base64

coor_addr = "Insert IP Here"
ap_addr = "Insert IP Here"

 
_PEM_RE = re.compile(
    r"-----BEGIN (?:TRUSTED )?CERTIFICATE-----\s+"
    r"([A-Za-z0-9+/=\s]+?)"
    r"-----END (?:TRUSTED )?CERTIFICATE-----",
    re.S,
)

def pem_certfile_to_der(path: str) -> bytes:
    data = open(path, "rb").read()
    text = data.decode("ascii", errors="ignore")
    m = _PEM_RE.search(text)
    if not m:
        raise ValueError(f"No PEM certificate block found in {path}")
    b64 = re.sub(r"\s+", "", m.group(1))
    return base64.b64decode(b64)
                  

def chunks_for_len(n: int) -> bytes:
    chunks = (n + 1023) // 1024
    return (str(chunks).encode() + b"\n")

async def write_framed(writer, blob: bytes):
    writer.write(chunks_for_len(len(blob)))
    await writer.drain()
    writer.write(blob)
    await writer.drain()

async def read_framed(reader):
    chunks = await reader.readline()
    if not chunks:
        return b""
    chunks = int(chunks[:-1])
    data = b""
    for _ in range(chunks):
        data += await reader.read(1024)
    return data    

async def runTask(addr,ssl_ctx):
    t0 = time.perf_counter()
    reader, writer = await asyncio.open_connection(
    addr, 5007, ssl=ssl_ctx, family=socket.AF_INET
    ) 
    t_handshake = time.perf_counter()

    await write_framed(writer, b'Agent_Start')
    t_sendReq = time.perf_counter()


    app_sequence = await read_framed(reader)
    t_done  = time.perf_counter()

    bootApp = app_sequence[0:3115].decode('utf-8')
    code = app_sequence[3115:3119].decode('utf-8')
    encrypted_file = app_sequence[3119:]


    with open("encrypted_file.txt", "wb") as file:
        file.write(encrypted_file)

    if not bootApp:
        raise RuntimeError("server closed before sending response")

    writer.close()
    await writer.wait_closed()

    await runTaskAttest(coor_addr,ssl_ctx)

async def runTaskAttest(addr,ssl_ctx):
    t0 = time.perf_counter()
    reader, writer = await asyncio.open_connection(
    addr, 5007, ssl=ssl_ctx, family=socket.AF_INET
    ) 
    t_handshake = time.perf_counter()

    client_cert_der = pem_certfile_to_der("client.crt")
    await write_framed(writer, b'Agent_Attest'+client_cert_der)
    t_sendReq = time.perf_counter()

    attributes =  await read_framed(reader)
    t_resp  = time.perf_counter()

    if not attributes:
        raise RuntimeError("server closed before sending response")

    writer.close()
    await writer.wait_closed()

    t_done  = time.perf_counter()


    print(
        "Client timings ms:",
        f"handshake={ (t_handshake - t0)*1000:.2f}",
        f"Request={ (t_sendReq - t_handshake)*1000:.2f}",
        f"Resp={ (t_resp - t_sendReq)*1000:.2f}",
        f"Decrypt={ (t_done - t_resp)*1000:.2f}",
        f"total={ (t_done - t0)*1000:.2f}",
    )



async def main():

    i = 0
    ssl_ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
    ssl_ctx.check_hostname = False
    ssl_ctx.verify_mode = ssl.CERT_NONE  # we verify via RA-TLS after handshake
    ssl_ctx.load_cert_chain('client.crt', 'client.key')

    port = random.randrange(2550,5000)

    tasks = []
    while i < 10000:  
        await asyncio.sleep(0.0001)
        task = asyncio.create_task(runTask(ap_addr,ssl_ctx))
        #task = asyncio.create_task(runTaskAttest1(addr,ssl_ctx))
        #task = asyncio.create_task(runTaskAttest2(addr,ssl_ctx))
        tasks.append(task)
        i+=1
    await asyncio.gather(*tasks)



if __name__ == '__main__':
    #main()
    asyncio.run(main())


