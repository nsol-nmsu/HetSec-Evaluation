import os
import time
import random
import socket
import json
import asyncio
import ssl 
import re
import base64


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
                  


#assures that packets are not dropping, if they are we begin to resend the ones that dropped
 

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

async def main():

    ssl_ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
    ssl_ctx.check_hostname = False
    ssl_ctx.verify_mode = ssl.CERT_NONE  # we verify via RA-TLS after handshake
    ssl_ctx.load_cert_chain('client.crt', 'client.key')

    addr = "20.83.35.85"
    addr = "57.154.240.53"
    port = random.randrange(2550,5000)

    t0 = time.perf_counter()
    reader, writer = await asyncio.open_connection(
    addr, 5007, ssl=ssl_ctx, family=socket.AF_INET
    ) 
    t_handshake = time.perf_counter()

    client_cert_der = pem_certfile_to_der("client.crt")
    await write_framed(writer, b'Coordinator_Attest_1'+client_cert_der)
    t_sendReq = time.perf_counter()

    key_IV =  await read_framed(reader)
    t_resp  = time.perf_counter()

    if not key_IV:
        raise RuntimeError("server closed before sending response")

    writer.close()
    await writer.wait_closed()

    coor_key = key_IV[0:-16]
    coor_IV = key_IV[-16:]

    t_done  = time.perf_counter()


    print(
        "Client timings ms:",
        f"handshake={ (t_handshake - t0)*1000:.2f}",
        f"Request={ (t_sendReq - t_handshake)*1000:.2f}",
        f"Resp={ (t_resp - t_sendReq)*1000:.2f}",
        f"Decrypt={ (t_done - t_resp)*1000:.2f}",
        f"total={ (t_done - t0)*1000:.2f}",
    )

    #TODO: Decrypt app and then run the file


if __name__ == '__main__':
    #main()
    asyncio.run(main())


