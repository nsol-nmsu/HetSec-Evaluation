import os
import time
import random
import socket
import json
import asyncio
import ssl 
import re
import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
from attest_util import gen_tdx_quote_bytes

key = bytes.fromhex("C09A05030C15CBC957E60D0678BD47451367E9BBC427EC5B5C60E9C6B286C87B")
iv = bytes.fromhex("22dc9c199a5d430a95a4020b1348130a")
cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
encryptor = cipher.encryptor()
padder = padding.PKCS7(128).padder()
encryptor = cipher.encryptor()    
my_quote = gen_tdx_quote_bytes("config.json")

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

    await write_framed(writer, b'Coordinator_Start')
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

    await runTaskAttest1(addr,ssl_ctx)

async def runTaskAttest1(addr,ssl_ctx):
    t0 = time.perf_counter()
    reader, writer = await asyncio.open_connection(
    addr, 5007, ssl=ssl_ctx, family=socket.AF_INET
    ) 
    t_handshake = time.perf_counter()

    await write_framed(writer, b'Coordinator_Attest_1'+my_quote)
    t_sendReq = time.perf_counter()

    key_IV =  await read_framed(reader)
    t_resp  = time.perf_counter()

    if not key_IV:
        raise RuntimeError("server closed before sending response")

    writer.close()
    await writer.wait_closed()

    coor_key = key_IV[0:-16]
    coor_IV = key_IV[-16:]

    cipher = Cipher(algorithms.AES(coor_key), modes.CBC(coor_IV), backend=default_backend())
    decryptor = cipher.decryptor()
    unpadder = padding.PKCS7(128).unpadder()
    with open("encrypted_file.txt", 'rb') as file:
        encyrpted_file = file.read()
    #decrypted_weights = decryptor.update(encyrpted_file) + decryptor.finalize()

    t_done  = time.perf_counter()
    await runTaskAttest2(addr,ssl_ctx)


async def runTaskAttest2(addr,ssl_ctx):
    t0 = time.perf_counter()
    reader, writer = await asyncio.open_connection(
    addr, 5007, ssl=ssl_ctx, family=socket.AF_INET
    ) 
    t_handshake = time.perf_counter()

    await write_framed(writer, b'Coordinator_Attest_2'+my_quote)
    t_sendReq = time.perf_counter()

    attriubtes = await read_framed(reader)


    if not attriubtes:
        raise RuntimeError("server closed before sending response")

    writer.close()
    await writer.wait_closed()

    t_done  = time.perf_counter()


async def main():

    i = 0
    ssl_ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
    ssl_ctx.check_hostname = False
    ssl_ctx.verify_mode = ssl.CERT_NONE  # we verify via RA-TLS after handshake
    ssl_ctx.load_cert_chain('client.crt', 'client.key')

    addr = "20.83.35.85"
    addr = "57.154.240.53"
    port = random.randrange(2550,5000)

    tasks = []
    while i < 150:  
        await asyncio.sleep(0.0001)
        task = asyncio.create_task(runTask(addr,ssl_ctx))
        tasks.append(task)
        i+=1
    await asyncio.gather(*tasks)



if __name__ == '__main__':
    #main()
    asyncio.run(main())


