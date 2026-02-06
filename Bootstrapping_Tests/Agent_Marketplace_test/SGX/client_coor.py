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
                  

def chunks_for_len(n: int) -> bytes:
    chunks = (n + 1023) // 1024
    return (str(chunks).encode() + b"\n")

async def write_framed(writer, blob: bytes):
    writer.write(chunks_for_len(len(blob)))
    await writer.drain()
    writer.write(blob)
    await writer.drain()

async def main():

    i = 0
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

    await write_framed(writer, b'Coordinator_Start')
    t_sendReq = time.perf_counter()


    app_sequence = await reader.readline()
    t_done  = time.perf_counter()

    bootApp = app_sequence[0:3136]
    code = app_sequence[3136:3140]
    encrypted_file = app_sequence[3140:]


    with open("encrypted_file.txt", "w") as file:
        file.write(encrypted_file)

    if not bootapp:
        raise RuntimeError("server closed before sending response")

    writer.close()
    await writer.wait_closed()

    print(
        "Client timings ms:",
        f"handshake={ (t_handshake - t0)*1000:.2f}",
        f"Request={ (t_sendReq - t_handshake)*1000:.2f}",
        f"Response={ (t_done - t_sendReq)*1000:.2f}",
        f"total={ (t_done - t0)*1000:.2f}",
    )


if __name__ == '__main__':
    #main()
    asyncio.run(main())


